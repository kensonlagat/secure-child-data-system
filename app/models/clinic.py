"""Clinic visit log (#52). All clinical text is encrypted. Append-only: a correction is a
new entry, never an edit (the app role has SELECT and INSERT only)."""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class ClinicVisit(db.Model):
    __tablename__ = "clinic_visits"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    visited_at = db.Column(db.DateTime, nullable=False)
    complaint = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    treatment = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    medicines_given = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    follow_up = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    immunisation = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    recorder = db.relationship("User")
