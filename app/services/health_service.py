"""Health entries, medication schedules and the administration log (#57). Access is
decided in access_service.py. Audit rows carry ids, types and outcomes, never health text."""

import re
from datetime import date, datetime, time, timedelta

from app import db
from app.models.health import (
    ADMINISTRATION_OUTCOMES,
    HEALTH_ENTRY_TYPES,
    HealthEntry,
    MedicationAdministration,
    MedicationSchedule,
)
from app.services.audit_service import log_action

TIME_PATTERN = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
MISSED_GRACE = timedelta(hours=1)
MISSED_LOOKBACK_DAYS = 7


class HealthError(ValueError):
    """Invalid input. The message is safe to show."""


def _text(form, field, limit, required=True):
    value = (form.get(field) or "").strip()
    if required and not value:
        raise HealthError(f"Enter the {field.replace('_', ' ')}.")
    if len(value) > limit:
        raise HealthError(f"Keep the {field.replace('_', ' ')} under {limit} characters.")
    return value or None


def add_entry(actor, child, form):
    entry_type = (form.get("entry_type") or "").strip()
    if entry_type not in HEALTH_ENTRY_TYPES:
        raise HealthError("Choose appointment or immunisation.")
    try:
        entry_at = datetime.fromisoformat((form.get("entry_at") or "").strip())
    except ValueError as error:
        raise HealthError("Enter the date and time.") from error
    entry = HealthEntry(child_record_id=child.id, entry_type=entry_type, entry_at=entry_at,
                        details=_text(form, "details", 1000), recorded_by=actor.id)
    db.session.add(entry)
    db.session.flush()
    log_action(user_id=actor.id, action="health_entry_added", target_record_type="child_record",
               target_record_id=child.id, details=f"Added {entry_type} {entry.id}")
    return entry


def add_schedule(actor, child, form):
    times = [t.strip() for t in (form.get("daily_times") or "").split(",") if t.strip()]
    if not times or len(times) > 6 or not all(TIME_PATTERN.fullmatch(t) for t in times):
        raise HealthError("Enter up to six daily times as HH:MM, separated by commas.")
    try:
        start = date.fromisoformat((form.get("start_date") or "").strip())
        end_raw = (form.get("end_date") or "").strip()
        end = date.fromisoformat(end_raw) if end_raw else None
    except ValueError as error:
        raise HealthError("Enter the start date (and end date, if any) as dates.") from error
    if end and end < start:
        raise HealthError("The end date can't be before the start date.")
    schedule = MedicationSchedule(child_record_id=child.id, medicine=_text(form, "medicine", 120),
                                  dose=_text(form, "dose", 120), daily_times=",".join(sorted(set(times))),
                                  start_date=start, end_date=end, created_by=actor.id)
    db.session.add(schedule)
    db.session.flush()
    log_action(user_id=actor.id, action="medication_schedule_added", target_record_type="child_record",
               target_record_id=child.id, details=f"Added medication schedule {schedule.id}")
    return schedule


def stop_schedule(actor, schedule):
    if not schedule.is_active:
        raise HealthError("That schedule is already stopped.")
    schedule.is_active, schedule.stopped_by, schedule.stopped_at = False, actor.id, datetime.utcnow()
    log_action(user_id=actor.id, action="medication_schedule_stopped", target_record_type="child_record",
               target_record_id=schedule.child_record_id, details=f"Stopped medication schedule {schedule.id}")


def record_dose(actor, schedule, form):
    outcome = (form.get("outcome") or "").strip()
    if outcome not in ADMINISTRATION_OUTCOMES:
        raise HealthError("Choose given, refused or missed.")
    try:
        scheduled_for = datetime.fromisoformat((form.get("scheduled_for") or "").strip())
    except ValueError as error:
        raise HealthError("Choose the scheduled dose.") from error
    if scheduled_for.strftime("%H:%M") not in schedule.times:
        raise HealthError("That time is not on this schedule.")
    if MedicationAdministration.query.filter_by(schedule_id=schedule.id, scheduled_for=scheduled_for).first():
        raise HealthError("That dose is already recorded.")
    entry = MedicationAdministration(schedule_id=schedule.id, scheduled_for=scheduled_for, outcome=outcome,
                                     given_at=datetime.now() if outcome == "given" else None,
                                     note=_text(form, "note", 300, required=False), recorded_by=actor.id)
    db.session.add(entry)
    db.session.flush()
    log_action(user_id=actor.id, action="medication_dose_recorded", target_record_type="child_record",
               target_record_id=schedule.child_record_id, details=f"Dose for schedule {schedule.id}: {outcome}")
    return entry


def _due_doses(schedule, since, until):
    day = max(schedule.start_date, since.date())
    last = min(schedule.end_date or until.date(), until.date())
    while day <= last:
        for hhmm in schedule.times:
            due = datetime.combine(day, time.fromisoformat(hhmm))
            if since <= due <= until:
                yield due
        day += timedelta(days=1)


def missed_doses(child_record_ids, now=None):
    """[(schedule, due time)] for scheduled doses with no log entry after the grace period,
    over the last MISSED_LOOKBACK_DAYS days. A dose logged as 'missed' counts too."""
    now = now or datetime.now()
    since = now - timedelta(days=MISSED_LOOKBACK_DAYS)
    result = []
    for schedule in MedicationSchedule.query.filter(MedicationSchedule.child_record_id.in_(child_record_ids),
                                                    MedicationSchedule.is_active.is_(True)).all():
        logged = {a.scheduled_for: a.outcome for a in
                  MedicationAdministration.query.filter_by(schedule_id=schedule.id).all()}
        for due in _due_doses(schedule, since, now - MISSED_GRACE):
            if logged.get(due) in (None, "missed"):
                result.append((schedule, due))
    return sorted(result, key=lambda pair: pair[1])


def todays_doses(schedule, now=None):
    now = now or datetime.now()
    start = datetime.combine(now.date(), time.min)
    return list(_due_doses(schedule, start, datetime.combine(now.date(), time.max)))


def overview(child_record_id):
    entries = HealthEntry.query.filter_by(child_record_id=child_record_id).order_by(HealthEntry.entry_at.desc()).all()
    schedules = MedicationSchedule.query.filter_by(child_record_id=child_record_id).order_by(
        MedicationSchedule.is_active.desc(), MedicationSchedule.id).all()
    log = (MedicationAdministration.query.join(MedicationSchedule)
           .filter(MedicationSchedule.child_record_id == child_record_id)
           .order_by(MedicationAdministration.scheduled_for.desc()).limit(50).all())
    return entries, schedules, log
