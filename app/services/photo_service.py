"""Child photo storage (#87). Reuses #66's image handling (signature check, Pillow
re-encoding under an explicit pixel limit, EXIF removed) with a photo-specific key. Each row
is inserted once, complete (the table is append-only), so the associated data uses a random
blob id generated before the insert rather than the database id."""

import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app

from app import db
from app.models.photo import ChildPhoto
from app.services.audit_service import log_action
from app.services.document_service import DocumentError, detect_type, reencode_image

MAX_PHOTO_BYTES = 5 * 1024 * 1024


class PhotoIntegrityError(Exception):
    """A stored photo failed to decrypt."""


def _key():
    secret = current_app.config["FIELD_ENCRYPTION_KEY"].encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"photo-v1").derive(secret)


def _aad(child_record_id, blob_id):
    return f"photo:{child_record_id}:{blob_id}".encode()


def store(actor, child, data):
    if not data:
        raise DocumentError("Choose a photo.", "empty")
    if len(data) > MAX_PHOTO_BYTES:
        raise DocumentError("Photos can be at most 5 MB.", "too_large")
    content_type = detect_type(data)
    if content_type not in ("image/jpeg", "image/png"):
        raise DocumentError("Photos must be JPEG or PNG.", "type")
    clean = reencode_image(data, content_type)
    blob_id = secrets.token_hex(16)
    nonce = os.urandom(12)
    photo = ChildPhoto(child_record_id=child.id, blob_id=blob_id, content_type=content_type, uploaded_by=actor.id,
                       ciphertext=nonce + AESGCM(_key()).encrypt(nonce, clean, _aad(child.id, blob_id)))
    db.session.add(photo)
    db.session.flush()
    log_action(user_id=actor.id, action="child_photo_uploaded", target_record_type="child_record",
               target_record_id=child.id, details=f"Uploaded photo {photo.id}")
    return photo


def current(child_record_id):
    return (ChildPhoto.query.filter_by(child_record_id=child_record_id)
            .order_by(ChildPhoto.uploaded_at.desc(), ChildPhoto.id.desc()).first())


def read(photo):
    blob = bytes(photo.ciphertext)
    try:
        return AESGCM(_key()).decrypt(blob[:12], blob[12:], _aad(photo.child_record_id, photo.blob_id))
    except (InvalidTag, ValueError) as error:
        raise PhotoIntegrityError() from error
