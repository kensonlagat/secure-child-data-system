"""Child photos (#87). Encrypted (AES-256-GCM, own derived key, bound to the child and a
random blob id as associated data) and append-only: rows are written once, complete, and a
new photo replaces the old one by being newer. Shown only on the record page, never in lists,
and only when photo consent is given (#63's has_consent)."""

from datetime import datetime

from app import db


class ChildPhoto(db.Model):
    __tablename__ = "child_photos"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    blob_id = db.Column(db.String(32), nullable=False, unique=True)  # random, generated before the insert
    content_type = db.Column(db.String(20), nullable=False)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
