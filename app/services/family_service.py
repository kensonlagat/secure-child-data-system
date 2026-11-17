"""Family visits and tracing (#58). Access is decided in access_service.py. Audit rows carry
ids, relationship and status only, never names or notes."""

from datetime import datetime

from app import db
from app.models.family import TRACING_STATUSES, VISITOR_RELATIONSHIPS, FamilyTracing, FamilyVisit
from app.services.audit_service import log_action


class FamilyError(ValueError):
    """Invalid input. The message is safe to show."""


def add_visit(actor, child, form):
    name = (form.get("visitor_name") or "").strip()
    relationship = (form.get("relationship") or "").strip()
    notes = (form.get("notes") or "").strip()
    supervised = (form.get("supervised") or "").strip()
    if not name or len(name) > 120:
        raise FamilyError("Enter the visitor's name (up to 120 characters).")
    if relationship not in VISITOR_RELATIONSHIPS:
        raise FamilyError("Choose the visitor's relationship.")
    if supervised not in ("yes", "no"):
        raise FamilyError("Say whether the visit was supervised.")
    if len(notes) > 2000:
        raise FamilyError("Keep the notes under 2000 characters.")
    try:
        visit_at = datetime.fromisoformat((form.get("visit_at") or "").strip())
    except ValueError as error:
        raise FamilyError("Enter the visit date and time.") from error
    if visit_at > datetime.now():
        raise FamilyError("The visit can't be in the future.")
    visit = FamilyVisit(child_record_id=child.id, visit_at=visit_at, visitor_name=name, relationship=relationship,
                        supervised=supervised == "yes", notes=notes or None, recorded_by=actor.id)
    db.session.add(visit)
    db.session.flush()
    log_action(user_id=actor.id, action="family_visit_recorded", target_record_type="child_record",
               target_record_id=child.id,
               details=f"Recorded visit {visit.id} ({relationship}, {'supervised' if visit.supervised else 'unsupervised'})")
    return visit


def set_tracing(actor, child, form):
    status = (form.get("status") or "").strip()
    if status not in TRACING_STATUSES:
        raise FamilyError("Choose a family tracing status.")
    tracing = FamilyTracing.query.filter_by(child_record_id=child.id).first()
    old = tracing.status if tracing else "none"
    if tracing is None:
        tracing = FamilyTracing(child_record_id=child.id, status=status, updated_by=actor.id)
        db.session.add(tracing)
    elif tracing.status == status:
        return False
    else:
        tracing.status, tracing.updated_by, tracing.updated_at = status, actor.id, datetime.utcnow()
    db.session.flush()
    log_action(user_id=actor.id, action="family_tracing_updated", target_record_type="child_record",
               target_record_id=child.id, details=f"Family tracing {old} -> {status}")
    return True


def visits(child_record_id):
    """Chronological (oldest first), as the issue asks."""
    return FamilyVisit.query.filter_by(child_record_id=child_record_id).order_by(FamilyVisit.visit_at, FamilyVisit.id).all()


def tracing(child_record_id):
    return FamilyTracing.query.filter_by(child_record_id=child_record_id).first()
