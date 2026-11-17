"""Admission and intake for children's-home records (#54): how and why a child came into
care. One intake per child. The placement reason, committal order reference and the
children's officer's name are encrypted."""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

REFERRAL_SOURCES = ("childrens_officer", "police", "court", "hospital", "community", "family", "other")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class IntakeRecord(db.Model):
    __tablename__ = "intake_records"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, unique=True)
    referral_source = db.Column(db.String(30), nullable=False)
    admission_date = db.Column(db.Date, nullable=False)
    placement_reason = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    committal_order_reference = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    childrens_officer = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)
