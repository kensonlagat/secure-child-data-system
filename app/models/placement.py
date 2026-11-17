"""Placement, reintegration and aftercare (#59).

Recording where a child goes next never touches `legal_status`: legal outcomes still go
through the two-person workflow (hard rule 3). Placements are append-only; aftercare
follow-ups are scheduled and later marked done.
"""

from datetime import date, datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

PLACEMENT_OUTCOMES = ("family_reunification", "foster_care", "kinship_care", "adoption", "leaving_care")
# Outcomes that normally need a legal status change; the page points to the workflow.
OUTCOMES_NEEDING_LEGAL_WORKFLOW = {"adoption", "foster_care"}


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class Placement(db.Model):
    """Append-only: the app role may insert and read, never update or delete."""

    __tablename__ = "placements"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    outcome = db.Column(db.String(30), nullable=False)
    exit_date = db.Column(db.Date, nullable=False)
    destination_notes = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AftercareFollowUp(db.Model):
    __tablename__ = "aftercare_followups"

    id = db.Column(db.Integer, primary_key=True)
    placement_id = db.Column(db.Integer, db.ForeignKey("placements.id"), nullable=False, index=True)
    due_date = db.Column(db.Date, nullable=False, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    completed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    notes = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    placement = db.relationship("Placement")

    @property
    def is_overdue(self):
        return self.completed_at is None and self.due_date < date.today()
