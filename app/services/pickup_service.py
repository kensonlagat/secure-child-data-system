"""Adding and revoking authorised collectors (#51). Access is decided in access_service.py.
Audit rows carry ids and the relationship only, never names, phone or ID numbers."""

import re
from datetime import datetime

from app import db
from app.models.pickup import RELATIONSHIPS, AuthorisedCollector
from app.services.audit_service import log_action

E164_PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
ID_NUMBER_PATTERN = re.compile(r"^[A-Za-z0-9]{5,20}$")


class PickupError(ValueError):
    """Invalid collector input. The message is safe to show."""


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
    return (AuthorisedCollector.query.filter_by(child_record_id=child_record_id, is_active=True)
            .order_by(AuthorisedCollector.id).all())


def add(actor, child, full_name, relationship, phone, id_number):
    collector = AuthorisedCollector(child_record_id=child.id, full_name=full_name, relationship=relationship,
                                    phone_number=phone, national_id_number=id_number, added_by=actor.id)
    db.session.add(collector)
    db.session.flush()
    log_action(user_id=actor.id, action="collector_added", target_record_type="child_record",
               target_record_id=child.id, details=f"Added collector {collector.id} ({relationship})")
    return collector


def revoke(actor, collector):
    if not collector.is_active:
        raise PickupError("That collector was already removed.")
    collector.is_active = False
    collector.revoked_by = actor.id
    collector.revoked_at = datetime.utcnow()
    log_action(user_id=actor.id, action="collector_revoked", target_record_type="child_record",
               target_record_id=collector.child_record_id, details=f"Revoked collector {collector.id}")
