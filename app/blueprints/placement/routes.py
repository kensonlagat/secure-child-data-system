"""Placement, reintegration and aftercare (#59). The assigned social worker writes; legal
officers and the home manager read. These routes never change `legal_status`."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied, require_role
from app.models.child_record import ChildRecord
from app.models.placement import OUTCOMES_NEEDING_LEGAL_WORKFLOW, PLACEMENT_OUTCOMES, AftercareFollowUp, Placement
from app.services import placement_service as placement
from app.services.access_service import can_read_placement, can_write_placement, get_accessible_records
from app.services.audit_service import log_action

placement_bp = Blueprint("placement", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not can_read_placement(current_user, record):
        audit_access_denied("Denied placement access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


def _post(record, action):
    if not can_write_placement(current_user, record):
        audit_access_denied("Refused to change a placement", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        action()
        flash("Saved.", "success")
    except placement.PlacementError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("placement.placement_page", record_id=record.id))


@placement_bp.route("/records/<int:record_id>")
@login_required
def placement_page(record_id):
    record = _record_or_404(record_id)
    log_action(user_id=current_user.id, action="placement_viewed", target_record_type="child_record",
               target_record_id=record.id, details="Viewed placement and aftercare")
    return render_template("placement/record.html", record=record, placements=placement.placements(record.id),
                           followups=placement.followups(record.id), outcomes=PLACEMENT_OUTCOMES,
                           needs_legal=OUTCOMES_NEEDING_LEGAL_WORKFLOW,
                           can_write=can_write_placement(current_user, record))


@placement_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def record_placement(record_id):
    record = _record_or_404(record_id)
    return _post(record, lambda: placement.record_placement(current_user, record, request.form))


@placement_bp.route("/placements/<int:placement_id>/followups", methods=["POST"])
@login_required
def add_followup(placement_id):
    entry = db.session.get(Placement, placement_id)
    record = _record_or_404(entry.child_record_id if entry else 0)
    return _post(record, lambda: placement.add_followup(current_user, entry, request.form))


@placement_bp.route("/followups/<int:followup_id>/complete", methods=["POST"])
@login_required
def complete_followup(followup_id):
    followup = db.session.get(AftercareFollowUp, followup_id)
    record = _record_or_404(followup.placement.child_record_id if followup else 0)
    return _post(record, lambda: placement.complete_followup(current_user, followup, request.form))


@placement_bp.route("/due")
@login_required
@require_role("social_worker", "home_manager", "legal_officer")
def due():
    readable = [r.id for r in get_accessible_records(current_user).filter(ChildRecord.institution_mode == "childrens_home")
                if can_read_placement(current_user, r)]
    items = placement.due_followups(readable) if readable else []
    log_action(user_id=current_user.id, action="aftercare_due_viewed", target_record_type="route",
               details=f"Viewed {len(items)} due follow-up(s)")
    return render_template("placement/due.html", followups=items, days=placement.DUE_WINDOW_DAYS)
