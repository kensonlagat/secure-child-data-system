"""Taking registers, correcting marks and absence alerts (#50).

Who may do what is decided in access_service.py (can_mark_attendance / can_read_attendance).
Audit rows carry ids, dates and counts only: never names, reasons or SMS text.
"""

from collections import Counter
from datetime import date, datetime, timedelta

from flask import current_app

from app import db
from app.models.attendance import (
    ATTENDANCE_STATUSES,
    AbsenceAlert,
    AttendanceCorrection,
    AttendanceMark,
    AttendanceRegister,
)
from app.models.child_record import ChildRecord
from app.models.school_class import Enrolment
from app.services.audit_service import log_action

REASON_MAX_LENGTH = 300
# The guardian SMS names nothing: no child, class or school detail (#50).
ABSENCE_SMS_TEXT = "Attendance notice: please contact the school about recent absences."


class AttendanceError(ValueError):
    """Invalid attendance input. The message is safe to show."""


def class_children(school_class):
    """Children currently enrolled in the class, deleted records excluded."""
    return (ChildRecord.query.join(Enrolment, Enrolment.child_record_id == ChildRecord.id)
            .filter(Enrolment.class_id == school_class.id, Enrolment.ended_on.is_(None),
                    ChildRecord.is_deleted.is_(False))
            .order_by(ChildRecord.id).all())


def get_register(school_class, register_date):
    return AttendanceRegister.query.filter_by(class_id=school_class.id, register_date=register_date).first()


def save_register(actor, school_class, register_date, statuses, reason=None):
    """Save marks for one class and day. `statuses` maps child id -> status.

    Today: marks are created or changed directly. A past day: every change needs a reason
    and adds an append-only correction row. Future days are refused.
    """
    today = date.today()
    if register_date > today:
        raise AttendanceError("You can't take a register for a future date.")
    children = {child.id: child for child in class_children(school_class)}
    unknown = set(statuses) - set(children)
    if unknown:
        raise AttendanceError("The register lists a child who is not in this class.")
    for status in statuses.values():
        if status not in ATTENDANCE_STATUSES:
            raise AttendanceError("Choose present, absent, late or excused for each child.")
    is_past = register_date < today
    reason = (reason or "").strip()
    if len(reason) > REASON_MAX_LENGTH:
        raise AttendanceError(f"Keep the reason under {REASON_MAX_LENGTH} characters.")

    register = get_register(school_class, register_date)
    if register is None:
        register = AttendanceRegister(class_id=school_class.id, register_date=register_date, taken_by=actor.id)
        db.session.add(register)
        db.session.flush()
    existing = {mark.child_record_id: mark for mark in register.marks}

    corrections, newly_absent = 0, []
    for child_id, status in statuses.items():
        mark = existing.get(child_id)
        if mark is None:
            if is_past and not reason:
                raise AttendanceError("Marking a past day needs a reason.")
            mark = AttendanceMark(register_id=register.id, child_record_id=child_id, status=status)
            db.session.add(mark)
            db.session.flush()
            if is_past:
                db.session.add(AttendanceCorrection(mark_id=mark.id, old_status="unmarked", new_status=status,
                                                    reason=reason, corrected_by=actor.id))
                corrections += 1
            if status == "absent":
                newly_absent.append(child_id)
        elif mark.status != status:
            if is_past:
                if not reason:
                    raise AttendanceError("Changing a past day's register needs a reason.")
                db.session.add(AttendanceCorrection(mark_id=mark.id, old_status=mark.status, new_status=status,
                                                    reason=reason, corrected_by=actor.id))
                corrections += 1
            if status == "absent":
                newly_absent.append(child_id)
            mark.status = status
    db.session.flush()

    counts = Counter(statuses.values())
    summary = ", ".join(f"{status} {counts.get(status, 0)}" for status in ATTENDANCE_STATUSES)
    log_action(user_id=actor.id, action="attendance_corrected" if corrections else "attendance_taken",
               target_record_type="school_class", target_record_id=school_class.id,
               details=f"Register {register_date.isoformat()}: {summary}"
                       + (f"; {corrections} correction(s) with reason" if corrections else ""))
    for child_id in newly_absent:
        check_absence_alert(children[child_id])
    return register


def absences_in_window(child_id, window_days, as_of=None):
    as_of = as_of or date.today()
    return (AttendanceMark.query.join(AttendanceRegister)
            .filter(AttendanceMark.child_record_id == child_id, AttendanceMark.status == "absent",
                    AttendanceRegister.register_date > as_of - timedelta(days=window_days),
                    AttendanceRegister.register_date <= as_of)
            .count())


def check_absence_alert(child):
    """Alert the guardian once when absences in the window reach the threshold. Never blocks
    the register: SMS failures are recorded, not raised."""
    from app.services.sms_service import send_sms

    threshold = current_app.config["ATTENDANCE_ABSENCE_THRESHOLD"]
    window_days = current_app.config["ATTENDANCE_ALERT_WINDOW_DAYS"]
    absences = absences_in_window(child.id, window_days)
    if absences < threshold:
        return None
    since = datetime.utcnow() - timedelta(days=window_days)
    if AbsenceAlert.query.filter(AbsenceAlert.child_record_id == child.id, AbsenceAlert.created_at > since).first():
        return None  # already alerted in this window: once per threshold crossing
    outcome = "no_contact"
    if child.guardian_contact:
        try:
            send_sms(child.guardian_contact, ABSENCE_SMS_TEXT)
            outcome = "sent"
        except Exception:
            outcome = "failed"
    alert = AbsenceAlert(child_record_id=child.id, absences=absences, window_days=window_days, outcome=outcome)
    db.session.add(alert)
    db.session.flush()
    log_action(attempted_identifier="system:attendance", action=f"absence_alert_{outcome}",
               target_record_type="child_record", target_record_id=child.id,
               details=f"{absences} absences in {window_days} days")
    return alert
