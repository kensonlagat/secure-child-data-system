"""Care plan and case notes (#55). Only the assigned social worker writes; the home manager
reads everything; legal officers see only legal summaries. Out of scope is 404 (audited)."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.care_plan import GOAL_STATUSES, NOTE_CATEGORIES, CarePlanGoal
from app.models.child_record import ChildRecord
from app.services import care_plan_service as care
from app.services.access_service import (
    can_read_care_plan,
    can_read_legal_summaries,
    can_write_care_plan,
    get_accessible_records,
)
from app.services.audit_service import log_action

care_bp = Blueprint("care", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not (can_read_care_plan(current_user, record) or can_read_legal_summaries(current_user, record)):
        audit_access_denied("Denied care plan access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


def _require_writer(record):
    if not can_write_care_plan(current_user, record):
        audit_access_denied("Refused to write to a care plan", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)


@care_bp.route("/records/<int:record_id>")
@login_required
def care_page(record_id):
    record = _record_or_404(record_id)
    if can_read_care_plan(current_user, record):
        log_action(user_id=current_user.id, action="care_plan_viewed", target_record_type="child_record",
                   target_record_id=record.id, details="Viewed care plan and case notes")
        return render_template("care/plan.html", record=record, goals=care.goals(record.id), notes=care.notes(record.id),
                               can_write=can_write_care_plan(current_user, record), statuses=GOAL_STATUSES,
                               categories=NOTE_CATEGORIES)
    # Legal officers: legal-relevant summaries only, never goals or note bodies.
    summaries = care.legal_summaries(record.id)
    log_action(user_id=current_user.id, action="legal_summaries_viewed", target_record_type="child_record",
               target_record_id=record.id, details=f"Viewed {len(summaries)} legal summary(ies)")
    return render_template("care/legal_summaries.html", record=record, summaries=summaries)


def _post(record_id, action):
    record = _record_or_404(record_id)
    _require_writer(record)
    try:
        action(record)
        flash("Saved.", "success")
    except care.CarePlanError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("care.care_page", record_id=record.id))


@care_bp.route("/records/<int:record_id>/goals", methods=["POST"])
@login_required
def add_goal(record_id):
    return _post(record_id, lambda record: care.add_goal(current_user, record, request.form))


@care_bp.route("/goals/<int:goal_id>", methods=["POST"])
@login_required
def update_goal(goal_id):
    goal = db.session.get(CarePlanGoal, goal_id)
    return _post(goal.child_record_id if goal else 0, lambda record: care.update_goal(current_user, goal, request.form))


@care_bp.route("/records/<int:record_id>/notes", methods=["POST"])
@login_required
def add_note(record_id):
    return _post(record_id, lambda record: care.add_note(current_user, record, request.form))
