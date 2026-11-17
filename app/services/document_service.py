"""Document upload checks, encryption and download (#66). Permissions are decided in
access_service.py. Audit rows carry ids, types and a size bucket, never filenames or content.

Layers on upload: size limit; type from the file signature (never the filename or browser);
images re-encoded with Pillow under an explicit pixel limit (removes EXIF and anything
appended); PDFs with active-content keywords refused. The keyword check is one layer only:
the main protection is the forced download with nosniff and CSP sandbox on every response.
"""

import io
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app

from app import db
from app.models.document import Document, DocumentBlob
from app.services.audit_service import log_action

MAX_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000  # Pillow refuses anything larger (decompression-bomb guard)
MAX_IMAGE_SIDE = 8000
PDF_ACTIVE_TOKENS = (b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile", b"/OpenAction")
EXTENSIONS = {"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png"}


class DocumentError(ValueError):
    """Refused upload or action. `reason` is a short category for the audit log."""

    def __init__(self, message, reason="invalid"):
        super().__init__(message)
        self.reason = reason


class DocumentIntegrityError(Exception):
    """A stored blob failed to decrypt (tampered, swapped or wrong key)."""


def _key():
    secret = current_app.config["FIELD_ENCRYPTION_KEY"].encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"document-v1").derive(secret)


def _aad(document_id):
    return f"document:{document_id}".encode()


def encrypt(document_id, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(_key()).encrypt(nonce, data, _aad(document_id))


def decrypt(document_id, blob):
    try:
        return AESGCM(_key()).decrypt(blob[:12], blob[12:], _aad(document_id))
    except (InvalidTag, ValueError) as error:
        raise DocumentIntegrityError() from error


def detect_type(data):
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    return None


def reencode_image(data, content_type):
    """Decode and re-save the image: drops EXIF and anything appended. Oversized images are
    refused before or while decoding."""
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    # Only the decoder for the type already detected from the file's first bytes: Pillow never
    # falls back to trying another format.
    formats = ["JPEG"] if content_type == "image/jpeg" else ["PNG"]
    try:
        with Image.open(io.BytesIO(data), formats=formats) as image:
            if image.width > MAX_IMAGE_SIDE or image.height > MAX_IMAGE_SIDE \
                    or image.width * image.height > MAX_IMAGE_PIXELS:
                raise DocumentError("That image is too large.", "image_too_large")
            image.load()
            clean = image.convert("RGB") if content_type == "image/jpeg" else image.copy()
    except DocumentError:
        raise
    except Image.DecompressionBombError as error:
        raise DocumentError("That image is too large.", "image_too_large") from error
    except Exception as error:
        raise DocumentError("That image could not be read.", "image_unreadable") from error
    out = io.BytesIO()
    clean.save(out, format="JPEG" if content_type == "image/jpeg" else "PNG")
    return out.getvalue()


def check_upload(data):
    if not data:
        raise DocumentError("Choose a file.", "empty")
    if len(data) > MAX_BYTES:
        raise DocumentError("Files can be at most 10 MB.", "too_large")
    content_type = detect_type(data)
    if content_type is None:
        raise DocumentError("Only PDF, JPEG and PNG files are accepted.", "type")
    if content_type == "application/pdf":
        if any(token in data for token in PDF_ACTIVE_TOKENS):
            raise DocumentError("That PDF contains active content and was refused.", "pdf_active_content")
        return content_type, data
    return content_type, reencode_image(data, content_type)


def _size_bucket(size):
    return "under 1 MB" if size < 1024 * 1024 else ("1-5 MB" if size < 5 * 1024 * 1024 else "5-10 MB")


def store(actor, child, document_type, filename, data):
    content_type, clean = check_upload(data)
    document = Document(child_record_id=child.id, document_type=document_type,
                        original_filename=(filename or "upload")[:200], content_type=content_type,
                        size_bytes=len(clean), uploaded_by=actor.id)
    db.session.add(document)
    db.session.flush()
    db.session.add(DocumentBlob(document_id=document.id, ciphertext=encrypt(document.id, clean)))
    log_action(user_id=actor.id, action="document_uploaded", target_record_type="child_record",
               target_record_id=child.id,
               details=f"Uploaded {document_type} document {document.id} ({_size_bucket(len(clean))})")
    return document


def read(document):
    blob = db.session.get(DocumentBlob, document.id)
    if blob is None:
        raise DocumentIntegrityError()
    return decrypt(document.id, bytes(blob.ciphertext))


def extension(document):
    return EXTENSIONS.get(document.content_type, "bin")
