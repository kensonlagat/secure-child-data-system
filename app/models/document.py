"""Encrypted document storage (#66). Metadata in `documents`; the file itself, encrypted with
AES-256-GCM (document id bound in as associated data), in `document_blobs`, which is
append-only. Deletion is soft (is_deleted), administrator-only and OTP-gated."""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

DOCUMENT_TYPES = ("birth_certificate", "court_order", "medical_report")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    document_type = db.Column(db.String(30), nullable=False)
    original_filename = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    content_type = db.Column(db.String(30), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)


class DocumentBlob(db.Model):
    """Append-only: stored files can't be changed or removed by the app role."""

    __tablename__ = "document_blobs"

    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"), primary_key=True)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
