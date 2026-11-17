"""Family contact, visits and tracing (#58). Visits are append-only; the visitor's name
and notes are encrypted. Each child has one family tracing status, which can change."""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

VISITOR_RELATIONSHIPS = ("mother", "father", "sibling", "grandparent", "aunt_uncle", "other_relative", "other")
TRACING_STATUSES = ("not_started", "in_progress", "family_found", "no_family_traced", "reunified")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class FamilyVisit(db.Model):
    """Append-only: the app role may insert and read, never update or delete."""

    __tablename__ = "family_visits"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    visit_at = db.Column(db.DateTime, nullable=False)
    visitor_name = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    relationship = db.Column(db.String(20), nullable=False)
    supervised = db.Column(db.Boolean, nullable=False)
    notes = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class FamilyTracing(db.Model):
    __tablename__ = "family_tracing"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
