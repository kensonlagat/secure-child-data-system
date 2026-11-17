"""Individual care plan goals and case notes (#55).

Goals carry a review date and a status; an open goal past its review date is overdue.
Case notes are append-only (a correction is a new note). Goal text, note bodies and the
legal summaries are encrypted. Legal officers see only the legal summary of a note.
"""

from datetime import date, datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

GOAL_STATUSES = ("open", "achieved", "discontinued")
NOTE_CATEGORIES = ("welfare", "education", "health", "family", "legal", "other")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class CarePlanGoal(db.Model):
    __tablename__ = "care_plan_goals"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    goal = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    review_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(15), nullable=False, default="open")
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_overdue(self):
        return self.status == "open" and self.review_date < date.today()


class CaseNote(db.Model):
    """Append-only: the app role may insert and read, never update or delete."""

    __tablename__ = "case_notes"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    note_date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(15), nullable=False)
    body = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    legal_summary = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    author = db.relationship("User")
