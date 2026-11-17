"""Missing child alerts (#60). One action raises an alert; the home manager is alerted at
once (SMS with no child details) and sees it until it is resolved. Circumstances, actions
taken and the resolution notes are encrypted. At most one open alert per child."""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class MissingChildAlert(db.Model):
    __tablename__ = "missing_child_alerts"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    status = db.Column(db.String(10), nullable=False, default="open")  # open, resolved
    last_seen_at = db.Column(db.DateTime, nullable=False)
    circumstances = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    actions_taken = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    raised_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    raised_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    found_at = db.Column(db.DateTime, nullable=True)
    resolution_notes = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
