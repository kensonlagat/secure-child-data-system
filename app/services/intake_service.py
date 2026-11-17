"""Creating and updating intake records (#54). Access is decided in access_service.py.
Audit rows carry ids and field names only, never the reason, references or names."""

from datetime import date, datetime

from app import db
from app.models.intake import REFERRAL_SOURCES, IntakeRecord
from app.services.audit_service import log_action

LIMITS = {"placement_reason": 1000, "committal_order_reference": 60, "childrens_officer": 120}
FIELDS = ("referral_source", "admission_date", "placement_reason", "committal_order_reference", "childrens_officer")


class IntakeError(ValueError):
    """Invalid intake input. The message is safe to show."""


def validate(form):
    referral_source = (form.get("referral_source") or "").strip()
    if referral_source not in REFERRAL_SOURCES:
        raise IntakeError("Choose the referral source.")
    try:
        admission_date = date.fromisoformat((form.get("admission_date") or "").strip())
    except ValueError as error:
        raise IntakeError("Enter the admission date.") from error
    if admission_date > date.today():
        raise IntakeError("The admission date can't be in the future.")
    values = {"referral_source": referral_source, "admission_date": admission_date}
    for field, limit in LIMITS.items():
        value = (form.get(field) or "").strip()
        if len(value) > limit:
            raise IntakeError(f"Keep the {field.replace('_', ' ')} under {limit} characters.")
        values[field] = value or None
    if not values["placement_reason"]:
        raise IntakeError("Enter the reason for placement.")
    return values


def get(child_record_id):
    return IntakeRecord.query.filter_by(child_record_id=child_record_id).first()


def create(actor, child, values, *, audit=True):
    if get(child.id) is not None:
        raise IntakeError("This child already has an intake record.")
    intake = IntakeRecord(child_record_id=child.id, created_by=actor.id, **values)
    db.session.add(intake)
    db.session.flush()
    if audit:
        log_action(user_id=actor.id, action="intake_created", target_record_type="child_record",
                   target_record_id=child.id, details=f"Created intake {intake.id}")
    return intake


def update(actor, intake, values):
    changed = [field for field in FIELDS if getattr(intake, field) != values[field]]
    if not changed:
        return []
    for field in changed:
        setattr(intake, field, values[field])
    intake.updated_by = actor.id
    intake.updated_at = datetime.utcnow()
    log_action(user_id=actor.id, action="intake_updated", target_record_type="child_record",
               target_record_id=intake.child_record_id, details=f"Updated fields: {', '.join(changed)}")
    return changed
