"""Adding, confirming, rejecting and revoking authorised collectors (#51, #112).

Access is decided in access_service.py. Audit rows carry ids, the relationship and
outcomes only: never names, phone numbers, ID numbers or SMS text.
"""

import re
from datetime import datetime

from app import db
from app.models.pickup import RELATIONSHIPS, AuthorisedCollector
from app.services.audit_service import log_action

E164_PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
ID_NUMBER_PATTERN = re.compile(r"^[A-Za-z0-9]{5,20}$")
# Sent to the guardian on every addition, pending or active. Names nobody (#112).
GUARDIAN_NOTICE = ("A change was made to your child's authorised pickup list. "
                   "Contact the school if you did not request it.")


class PickupError(ValueError):
    """Invalid collector input or action. The message is safe to show."""


def validate(form):
    full_name = (form.get("full_name") or "").strip()
    relationship = (form.get("relationship") or "").strip()
    phone = (form.get("phone_number") or "").strip()
    id_number = (form.get("national_id_number") or "").strip().upper()
    if not full_name or len(full_name) > 120:
        raise PickupError("Enter the collector's full name (up to 120 characters).")
    if relationship not in RELATIONSHIPS:
        raise PickupError("Choose the collector's relationship to the child.")
    if not E164_PHONE_PATTERN.fullmatch(phone):
        raise PickupError("Enter the phone number in international format, e.g. +254712345678.")
    if not ID_NUMBER_PATTERN.fullmatch(id_number):
        raise PickupError("Enter the national ID number (5 to 20 letters or digits).")
    return full_name, relationship, phone, id_number


def active_collectors(child_record_id):
    """Only confirmed collectors: the gate never sees pending, rejected or revoked ones."""
    return (AuthorisedCollector.query.filter_by(child_record_id=child_record_id, status="active")
            .order_by(AuthorisedCollector.id).all())


def listed_collectors(child_record_id):
    """Pending and active collectors, for the management page."""
    return (AuthorisedCollector.query.filter(AuthorisedCollector.child_record_id == child_record_id,
                                             AuthorisedCollector.status.in_(("pending", "active")))
            .order_by(AuthorisedCollector.id).all())


def _notify_guardian(actor, child):
    """Generic SMS on every addition. Never blocks the change; the outcome is audited."""
    from app.services.sms_service import send_sms

    outcome = "no_contact"
    if child.guardian_contact:
        try:
            send_sms(child.guardian_contact, GUARDIAN_NOTICE)
            outcome = "sent"
        except Exception:
            outcome = "failed"
    log_action(user_id=actor.id, action=f"pickup_guardian_notice_{outcome}", target_record_type="child_record",
               target_record_id=child.id, details="Guardian notified of a pickup list change")


def add(actor, child, full_name, relationship, phone, id_number, *, confirmed):
    """Administrators add confirmed (active) collectors; teachers add pending ones."""
    collector = AuthorisedCollector(
        child_record_id=child.id, full_name=full_name, relationship=relationship, phone_number=phone,
        national_id_number=id_number, added_by=actor.id, status="active" if confirmed else "pending",
        decided_by=actor.id if confirmed else None, decided_at=datetime.utcnow() if confirmed else None,
    )
    db.session.add(collector)
    db.session.flush()
    log_action(user_id=actor.id, action="collector_added" if confirmed else "collector_pending",
               target_record_type="child_record", target_record_id=child.id,
               details=f"{'Added' if confirmed else 'Proposed'} collector {collector.id} ({relationship})")
    _notify_guardian(actor, child)
    return collector


def decide(actor, collector, *, confirm):
    """An administrator confirms or rejects a pending collector."""
    if collector.status != "pending":
        raise PickupError("That collector is not waiting for confirmation.")
    collector.status = "active" if confirm else "rejected"
    collector.decided_by = actor.id
    collector.decided_at = datetime.utcnow()
    if not confirm:
        collector.is_active = False
    log_action(user_id=actor.id, action="collector_confirmed" if confirm else "collector_rejected",
               target_record_type="child_record", target_record_id=collector.child_record_id,
               details=f"{'Confirmed' if confirm else 'Rejected'} collector {collector.id}")


def revoke(actor, collector):
    if collector.status not in ("pending", "active"):
        raise PickupError("That collector was already removed.")
    collector.status = "revoked"
    collector.is_active = False
    collector.revoked_by = actor.id
    collector.revoked_at = datetime.utcnow()
    log_action(user_id=actor.id, action="collector_revoked", target_record_type="child_record",
               target_record_id=collector.child_record_id, details=f"Revoked collector {collector.id}")
