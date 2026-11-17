"""Placements and aftercare follow-ups (#59). Access is decided in access_service.py.
Nothing here reads or writes `legal_status`. Audit rows carry ids, outcomes and dates only."""

from datetime import date, datetime, timedelta

from app import db
from app.models.child_record import ChildRecord
from app.models.placement import PLACEMENT_OUTCOMES, AftercareFollowUp, Placement
from app.services.audit_service import log_action

DUE_WINDOW_DAYS = 14


class PlacementError(ValueError):
    """Invalid input. The message is safe to show."""


def _date(raw, label):
    try:
        return date.fromisoformat((raw or "").strip())
    except ValueError as error:
        raise PlacementError(f"Enter the {label}.") from error


def record_placement(actor, child, form):
    outcome = (form.get("outcome") or "").strip()
    notes = (form.get("destination_notes") or "").strip()
    if outcome not in PLACEMENT_OUTCOMES:
        raise PlacementError("Choose the placement outcome.")
    if len(notes) > 1000:
        raise PlacementError("Keep the destination notes under 1000 characters.")
    exit_date = _date(form.get("exit_date"), "exit date")
    placement = Placement(child_record_id=child.id, outcome=outcome, exit_date=exit_date,
                          destination_notes=notes or None, recorded_by=actor.id)
    db.session.add(placement)
    db.session.flush()
    log_action(user_id=actor.id, action="placement_recorded", target_record_type="child_record",
               target_record_id=child.id, details=f"Recorded placement {placement.id}: {outcome}")
    return placement


def add_followup(actor, placement, form):
    followup = AftercareFollowUp(placement_id=placement.id, due_date=_date(form.get("due_date"), "follow-up date"),
                                 created_by=actor.id)
    db.session.add(followup)
    db.session.flush()
    log_action(user_id=actor.id, action="aftercare_followup_scheduled", target_record_type="child_record",
               target_record_id=placement.child_record_id,
               details=f"Scheduled follow-up {followup.id} for {followup.due_date.isoformat()}")
    return followup


def complete_followup(actor, followup, form):
    if followup.completed_at is not None:
        raise PlacementError("That follow-up is already done.")
    notes = (form.get("notes") or "").strip()
    if len(notes) > 1000:
        raise PlacementError("Keep the notes under 1000 characters.")
    followup.completed_at, followup.completed_by, followup.notes = datetime.utcnow(), actor.id, notes or None
    log_action(user_id=actor.id, action="aftercare_followup_completed", target_record_type="child_record",
               target_record_id=followup.placement.child_record_id, details=f"Completed follow-up {followup.id}")


def placements(child_record_id):
    return Placement.query.filter_by(child_record_id=child_record_id).order_by(Placement.exit_date.desc()).all()


def followups(child_record_id):
    return (AftercareFollowUp.query.join(Placement).filter(Placement.child_record_id == child_record_id)
            .order_by(AftercareFollowUp.due_date).all())


def due_followups(record_ids, days=DUE_WINDOW_DAYS, today=None):
    """Open follow-ups that are overdue or due within `days`, for readable record ids."""
    today = today or date.today()
    return (AftercareFollowUp.query.join(Placement).join(ChildRecord, ChildRecord.id == Placement.child_record_id)
            .filter(Placement.child_record_id.in_(record_ids), AftercareFollowUp.completed_at.is_(None),
                    AftercareFollowUp.due_date <= today + timedelta(days=days), ChildRecord.is_deleted.is_(False))
            .order_by(AftercareFollowUp.due_date).all())
