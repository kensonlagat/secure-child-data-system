"""Court dates and the legal calendar (#56). Legal officers manage; the home manager and
the assigned social worker read. Out of scope is 404 (audited, bounded)."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied, require_role
from app.models.child_record import ChildRecord
from app.models.court import CourtHearing
from app.services import court_service
from app.services.access_service import can_manage_court, can_read_court, get_accessible_records
from app.services.audit_service import log_action

court_bp = Blueprint("court", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not can_read_court(current_user, record):
        audit_access_denied("Denied court calendar access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


def _require_manager(record):
    if not can_manage_court(current_user, record):
        audit_access_denied("Refused to change a court hearing", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)


@court_bp.route("/upcoming")
@login_required
@require_role("legal_officer", "home_manager", "social_worker")
def upcoming():
    """Overall upcoming hearings, limited to records the user can read."""
    readable = [r.id for r in get_accessible_records(current_user).filter(ChildRecord.institution_mode == "childrens_home")
                if can_read_court(current_user, r)]
    hearings = court_service.upcoming(readable) if readable else []
    log_action(user_id=current_user.id, action="court_calendar_viewed", target_record_type="route",
               details=f"Viewed {len(hearings)} upcoming hearing(s)")
    return render_template("court/upcoming.html", hearings=hearings, days=court_service.UPCOMING_DAYS)


@court_bp.route("/records/<int:record_id>")
@login_required
def hearings(record_id):
    record = _record_or_404(record_id)
    entries = court_service.for_child(record.id)
    log_action(user_id=current_user.id, action="court_hearings_viewed", target_record_type="child_record",
               target_record_id=record.id, details=f"Viewed {len(entries)} hearing(s)")
    return render_template("court/hearings.html", record=record, hearings=entries,
                           upcoming=court_service.upcoming([record.id]),
                           can_manage=can_manage_court(current_user, record))


@court_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def add_hearing(record_id):
    record = _record_or_404(record_id)
    _require_manager(record)
    try:
        court_service.add(current_user, record, court_service.validate(request.form))
        flash("Hearing added.", "success")
    except court_service.CourtError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("court.hearings", record_id=record.id))


@court_bp.route("/hearings/<int:hearing_id>", methods=["POST"])
@login_required
def update_hearing(hearing_id):
    hearing = db.session.get(CourtHearing, hearing_id)
    record = _record_or_404(hearing.child_record_id if hearing else 0)
    _require_manager(record)
    try:
        changed = court_service.update(current_user, hearing, court_service.validate(request.form))
        flash("Hearing updated." if changed else "No changes to save.", "success" if changed else "info")
    except court_service.CourtError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("court.hearings", record_id=record.id))
