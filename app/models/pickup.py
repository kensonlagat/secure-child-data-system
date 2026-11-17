"""Authorised pickup list (#51).

Collectors are added or revoked, never edited: to change details, revoke and add again, so
the history stays complete. The app role may update only the revoke columns (column-level
grant), never the collector's details.
"""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

RELATIONSHIPS = ("mother", "father", "guardian", "grandparent", "sibling", "relative", "driver", "other")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class AuthorisedCollector(db.Model):
    __tablename__ = "authorised_collectors"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    full_name = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    relationship = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    national_id_number = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    revoked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

    @property
    def id_hint(self):
        """Last three characters of the ID number: enough for the gate to confirm a match."""
        value = self.national_id_number or ""
        return f"…{value[-3:]}" if len(value) >= 3 else "…"
