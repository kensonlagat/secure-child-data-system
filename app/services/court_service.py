"""Court hearings (#56). Access is decided in access_service.py. Audit rows carry ids and
dates only, never case references or outcomes."""

from datetime import date, datetime, timedelta

from app import db
from app.models.child_record import ChildRecord
from app.models.court import CourtHearing
from app.services.audit_service import log_action

UPCOMING_DAYS = 14


class CourtError(ValueError):
    """Invalid input. The message is safe to show."""


def validate(form, *, existing=None):
    court = (form.get("court") or "").strip()
    reference = (form.get("case_reference") or "").strip()
    outcome = (form.get("outcome") or "").strip()
    if not court or len(court) > 120:
        raise CourtError("Enter the court (up to 120 characters).")
    if not reference or len(reference) > 60:
        raise CourtError("Enter the case reference (up to 60 characters).")
    if len(outcome) > 1000:
        raise CourtError("Keep the outcome under 1000 characters.")
    try:
        hearing_at = datetime.fromisoformat((form.get("hearing_at") or "").strip())
    except ValueError as error:
        raise CourtError("Enter the hearing date and time.") from error
    next_raw = (form.get("next_date") or "").strip()
    try:
        next_date = date.fromisoformat(next_raw) if next_raw else None
    except ValueError as error:
        raise CourtError("Enter the next date as a date.") from error
    if next_date and next_date < hearing_at.date():
        raise CourtError("The next date can't be before the hearing.")
    return {"court": court, "case_reference": reference, "outcome": outcome or None, "hearing_at": hearing_at,
            "next_date": next_date}


def add(actor, child, values):
    hearing = CourtHearing(child_record_id=child.id, created_by=actor.id, **values)
    db.session.add(hearing)
    db.session.flush()
    log_action(user_id=actor.id, action="court_hearing_added", target_record_type="child_record",
               target_record_id=child.id, details=f"Added hearing {hearing.id} on {hearing.hearing_at.date().isoformat()}")
    return hearing


def update(actor, hearing, values):
    changed = [field for field, value in values.items() if getattr(hearing, field) != value]
    if not changed:
        return []
    for field in changed:
        setattr(hearing, field, values[field])
    hearing.updated_by, hearing.updated_at = actor.id, datetime.utcnow()
    log_action(user_id=actor.id, action="court_hearing_updated", target_record_type="child_record",
               target_record_id=hearing.child_record_id, details=f"Updated hearing {hearing.id}: {', '.join(changed)}")
    return changed


def for_child(child_record_id):
    return CourtHearing.query.filter_by(child_record_id=child_record_id).order_by(CourtHearing.hearing_at.desc()).all()


def upcoming(record_ids_query, days=UPCOMING_DAYS, now=None):
    """Hearings in the next `days` days for the given (already scoped) record ids query."""
    now = now or datetime.now()
    return (CourtHearing.query.join(ChildRecord, ChildRecord.id == CourtHearing.child_record_id)
            .filter(CourtHearing.child_record_id.in_(record_ids_query), CourtHearing.hearing_at >= now,
                    CourtHearing.hearing_at < now + timedelta(days=days), ChildRecord.is_deleted.is_(False))
            .order_by(CourtHearing.hearing_at).all())
