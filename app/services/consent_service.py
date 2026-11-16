"""Recording and reading guardian consent (#63).

Who may do what is decided in access_service.py (can_record_consent / can_view_consent_details).
This module validates input and appends rows; it never updates or deletes one.
"""

from datetime import date

from app import db
from app.models.consent import CONSENT_STATUSES, CONSENT_TYPES, ConsentRecord
from app.services.audit_service import log_action

GUARDIAN_NAME_MAX_LENGTH = 120


class ConsentError(ValueError):
    """Invalid consent input. The message is safe to show."""


def validate(form):
    consent_type = (form.get("consent_type") or "").strip()
    status = (form.get("status") or "").strip()
    guardian_name = (form.get("guardian_name") or "").strip()
    if consent_type not in CONSENT_TYPES:
        raise ConsentError("Choose a consent type.")
    if status not in CONSENT_STATUSES:
        raise ConsentError("Choose whether consent was given or withdrawn.")
    if not guardian_name or len(guardian_name) > GUARDIAN_NAME_MAX_LENGTH:
        raise ConsentError(f"Enter the guardian's name (up to {GUARDIAN_NAME_MAX_LENGTH} characters).")
    try:
        effective_date = date.fromisoformat((form.get("effective_date") or "").strip())
    except ValueError as error:
        raise ConsentError("Enter the date the guardian gave or withdrew consent.") from error
    if effective_date > date.today():
        raise ConsentError("The consent date can't be in the future.")
    return consent_type, status, effective_date, guardian_name


def record(actor, child, consent_type, status, effective_date, guardian_name):
    """Append one consent row and audit it (type and status only, never the guardian name)."""
    entry = ConsentRecord(child_record_id=child.id, consent_type=consent_type, status=status,
                          effective_date=effective_date, guardian_name=guardian_name, recorded_by=actor.id)
    db.session.add(entry)
    db.session.flush()
    log_action(user_id=actor.id, action="consent_recorded", target_record_type="child_record",
               target_record_id=child.id, details=f"Consent {consent_type}: {status}")
    return entry


def history(child_record_id):
    return (ConsentRecord.query.filter_by(child_record_id=child_record_id)
            .order_by(ConsentRecord.recorded_at.desc(), ConsentRecord.id.desc()).all())


def current(child_record_id):
    """Latest row per consent type, or None when nothing was ever recorded."""
    latest = {consent_type: None for consent_type in CONSENT_TYPES}
    for entry in reversed(history(child_record_id)):
        latest[entry.consent_type] = entry
    return latest


def has_consent(child_record_id, consent_type):
    """True only when the latest row for this type says given. Missing means no consent:
    callers such as photo display (#87) must hide content unless this returns True."""
    entry = current(child_record_id).get(consent_type)
    return entry is not None and entry.status == "given"
