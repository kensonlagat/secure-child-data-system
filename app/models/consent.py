"""Guardian consent records (#63), Data Protection Act 2019.

Append-only: giving or withdrawing consent adds a row; the latest row per type is the
current status. The app's database role has SELECT and INSERT only on this table, so a
recorded consent can never be edited or deleted.
"""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

CONSENT_TYPES = ("photo", "medical_treatment", "data_sharing")
CONSENT_STATUSES = ("given", "withdrawn")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class ConsentRecord(db.Model):
    __tablename__ = "consent_records"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    consent_type = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    effective_date = db.Column(db.Date, nullable=False)
    guardian_name = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    recorder = db.relationship("User")
