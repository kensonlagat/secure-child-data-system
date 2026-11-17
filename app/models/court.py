"""Court hearings and the legal calendar (#56). The case reference and outcome are
encrypted. Hearings are updated after they happen (outcome, next date), every change audited."""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class CourtHearing(db.Model):
    __tablename__ = "court_hearings"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    hearing_at = db.Column(db.DateTime, nullable=False, index=True)
    court = db.Column(db.String(120), nullable=False)
    case_reference = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    outcome = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    next_date = db.Column(db.Date, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)
