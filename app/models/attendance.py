"""Daily attendance registers (#50).

- One register per class per day; one mark per child in it.
- Same-day changes update the mark. Changes after the day add an append-only correction
  row with an encrypted reason (the app role can't update or delete corrections).
- Absence alerts are append-only too: one row per alert decision, so an alert fires at
  most once per window.
"""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

ATTENDANCE_STATUSES = ("present", "absent", "late", "excused")


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class AttendanceRegister(db.Model):
    __tablename__ = "attendance_registers"
    __table_args__ = (db.UniqueConstraint("class_id", "register_date", name="uq_attendance_register_class_date"),)

    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("school_classes.id"), nullable=False, index=True)
    register_date = db.Column(db.Date, nullable=False)
    taken_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    taken_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    marks = db.relationship("AttendanceMark", back_populates="register")


class AttendanceMark(db.Model):
    __tablename__ = "attendance_marks"
    __table_args__ = (db.UniqueConstraint("register_id", "child_record_id", name="uq_attendance_mark_child"),)

    id = db.Column(db.Integer, primary_key=True)
    register_id = db.Column(db.Integer, db.ForeignKey("attendance_registers.id"), nullable=False, index=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    status = db.Column(db.String(10), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    register = db.relationship("AttendanceRegister", back_populates="marks")


class AttendanceCorrection(db.Model):
    """Append-only: a change to a mark after its day, with the reason."""

    __tablename__ = "attendance_corrections"

    id = db.Column(db.Integer, primary_key=True)
    mark_id = db.Column(db.Integer, db.ForeignKey("attendance_marks.id"), nullable=False, index=True)
    old_status = db.Column(db.String(10), nullable=False)
    new_status = db.Column(db.String(10), nullable=False)
    reason = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    corrected_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    corrected_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AbsenceAlert(db.Model):
    """Append-only: one row per absence-alert decision for a child."""

    __tablename__ = "absence_alerts"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    absences = db.Column(db.Integer, nullable=False)
    window_days = db.Column(db.Integer, nullable=False)
    outcome = db.Column(db.String(20), nullable=False)  # sent, failed, no_contact
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
