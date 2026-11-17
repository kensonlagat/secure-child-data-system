"""Raising and resolving missing child alerts (#60). Access is decided in access_service.py.
The manager SMS and audit rows never carry child details or the encrypted text."""

from datetime import datetime

from app import db
from app.models.missing import MissingChildAlert
from app.models.user import Role, User
from app.services.audit_service import log_action

MANAGER_SMS = "URGENT: a child has been reported missing. Please check the system now."


class MissingError(ValueError):
    """Invalid input. The message is safe to show."""


def _text(form, field, limit, required):
    value = (form.get(field) or "").strip()
    if required and not value:
        raise MissingError(f"Enter the {field.replace('_', ' ')}.")
    if len(value) > limit:
        raise MissingError(f"Keep the {field.replace('_', ' ')} under {limit} characters.")
    return value or None


def _time(form, field, label):
    try:
        value = datetime.fromisoformat((form.get(field) or "").strip())
    except ValueError as error:
        raise MissingError(f"Enter the {label}.") from error
    if value > datetime.now():
        raise MissingError(f"The {label} can't be in the future.")
    return value


def open_alert(child_record_id):
    return MissingChildAlert.query.filter_by(child_record_id=child_record_id, status="open").first()


def latest_alert(child_record_id):
    """The open alert, or else the most recently raised one (so resolved alerts stay visible)."""
    return open_alert(child_record_id) or (MissingChildAlert.query.filter_by(child_record_id=child_record_id)
                                           .order_by(MissingChildAlert.raised_at.desc(), MissingChildAlert.id.desc())
                                           .first())


def open_alerts():
    return MissingChildAlert.query.filter_by(status="open").order_by(MissingChildAlert.raised_at).all()


def _alert_managers(actor, alert):
    """Immediate SMS to every active home manager. Never blocks raising the alert."""
    from app.services.sms_service import send_sms

    managers = User.query.join(Role).filter(Role.name == "home_manager", User.is_active.is_(True)).all()
    sent = failed = 0
    for manager in managers:
        try:
            send_sms(manager.phone_number, MANAGER_SMS)
            sent += 1
        except Exception:
            failed += 1
    log_action(user_id=actor.id, action="missing_child_manager_alerted", target_record_type="child_record",
               target_record_id=alert.child_record_id,
               details=f"Alert {alert.id}: manager SMS sent {sent}, failed {failed}, managers {len(managers)}")


def raise_alert(actor, child, form):
    if open_alert(child.id) is not None:
        raise MissingError("This child already has an open missing alert.")
    alert = MissingChildAlert(child_record_id=child.id, last_seen_at=_time(form, "last_seen_at", "time last seen"),
                              circumstances=_text(form, "circumstances", 2000, required=True),
                              actions_taken=_text(form, "actions_taken", 2000, required=False), raised_by=actor.id)
    db.session.add(alert)
    db.session.flush()
    log_action(user_id=actor.id, action="missing_child_raised", target_record_type="child_record",
               target_record_id=child.id,
               details=f"Raised alert {alert.id}; last seen {alert.last_seen_at.isoformat(timespec='minutes')}")
    _alert_managers(actor, alert)
    return alert


def update_actions(actor, alert, form):
    if alert.status != "open":
        raise MissingError("That alert is already resolved.")
    alert.actions_taken = _text(form, "actions_taken", 2000, required=True)
    log_action(user_id=actor.id, action="missing_child_actions_updated", target_record_type="child_record",
               target_record_id=alert.child_record_id, details=f"Updated actions on alert {alert.id}")


def resolve(actor, alert, form):
    if alert.status != "open":
        raise MissingError("That alert is already resolved.")
    found_at = _time(form, "found_at", "time found or returned")
    if found_at < alert.last_seen_at:
        raise MissingError("The time found can't be before the time last seen.")
    alert.found_at = found_at
    alert.resolution_notes = _text(form, "resolution_notes", 2000, required=True)
    alert.status, alert.resolved_by, alert.resolved_at = "resolved", actor.id, datetime.utcnow()
    log_action(user_id=actor.id, action="missing_child_resolved", target_record_type="child_record",
               target_record_id=alert.child_record_id,
               details=f"Resolved alert {alert.id}; found {found_at.isoformat(timespec='minutes')}")
