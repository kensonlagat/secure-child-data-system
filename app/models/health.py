"""Health and medication records for children's-home records (#57).

- Health entries (appointments, immunisations) are append-only, details encrypted.
- Medication schedules list a medicine, dose and daily times; they can be stopped.
- The administration log (who gave what, when, or why not) is append-only.
A scheduled dose with no log entry after the grace period counts as missed.
"""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

HEALTH_ENTRY_TYPES = ("appointment", "immunisation")
ADMINISTRATION_OUTCOMES = ("given", "refused", "missed")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class HealthEntry(db.Model):
    __tablename__ = "health_entries"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    entry_type = db.Column(db.String(20), nullable=False)
    entry_at = db.Column(db.DateTime, nullable=False)
    details = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class MedicationSchedule(db.Model):
    __tablename__ = "medication_schedules"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    medicine = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    dose = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    daily_times = db.Column(db.String(60), nullable=False)  # "08:00,20:00"
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    stopped_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    stopped_at = db.Column(db.DateTime, nullable=True)

    @property
    def times(self):
        return [t for t in (self.daily_times or "").split(",") if t]


class MedicationAdministration(db.Model):
    """Append-only: one row per scheduled dose that was given, refused or missed."""

    __tablename__ = "medication_administrations"

    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey("medication_schedules.id"), nullable=False, index=True)
    scheduled_for = db.Column(db.DateTime, nullable=False)
    outcome = db.Column(db.String(10), nullable=False)
    given_at = db.Column(db.DateTime, nullable=True)
    note = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    recorder = db.relationship("User")
