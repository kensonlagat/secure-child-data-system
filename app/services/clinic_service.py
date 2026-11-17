"""Recording and reading clinic visits (#52). Access is decided in access_service.py.
Audit rows carry ids and counts only, never clinical text."""

from datetime import datetime

from app import db
from app.models.clinic import ClinicVisit
from app.services.audit_service import log_action

LIMITS = {"complaint": 500, "treatment": 500, "medicines_given": 300, "follow_up": 300, "immunisation": 200}
REQUIRED = ("complaint", "treatment")


class ClinicError(ValueError):
    """Invalid clinic input. The message is safe to show."""


def validate(form):
    values = {}
    for field, limit in LIMITS.items():
        value = (form.get(field) or "").strip()
        if field in REQUIRED and not value:
            raise ClinicError(f"Enter the {field.replace('_', ' ')}.")
        if len(value) > limit:
            raise ClinicError(f"Keep the {field.replace('_', ' ')} under {limit} characters.")
        values[field] = value or None
    raw_time = (form.get("visited_at") or "").strip()
    try:
        visited_at = datetime.fromisoformat(raw_time) if raw_time else datetime.now()
    except ValueError as error:
        raise ClinicError("Enter the visit date and time.") from error
    if visited_at > datetime.now():
        raise ClinicError("The visit can't be in the future.")
    values["visited_at"] = visited_at
    return values


def record(actor, child, values):
    visit = ClinicVisit(child_record_id=child.id, recorded_by=actor.id, **values)
    db.session.add(visit)
    db.session.flush()
    log_action(user_id=actor.id, action="clinic_visit_recorded", target_record_type="child_record",
               target_record_id=child.id, details=f"Recorded clinic visit {visit.id}")
    return visit


def visits(child_record_id):
    return (ClinicVisit.query.filter_by(child_record_id=child_record_id)
            .order_by(ClinicVisit.visited_at.desc(), ClinicVisit.id.desc()).all())
