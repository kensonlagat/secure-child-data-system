"""Admission and intake (#54). Records come only from access_service; out of scope is 404
(audited, bounded). Every view and change is audited."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.models.intake import REFERRAL_SOURCES
from app.services import intake_service
from app.services.access_service import can_read_intake, can_write_intake, get_accessible_records
from app.services.audit_service import log_action

intake_bp = Blueprint("intake", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not can_read_intake(current_user, record):
        audit_access_denied("Denied intake access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


@intake_bp.route("/records/<int:record_id>")
@login_required
def intake_page(record_id):
    record = _record_or_404(record_id)
    intake = intake_service.get(record.id)
    log_action(user_id=current_user.id, action="intake_viewed", target_record_type="child_record",
               target_record_id=record.id, details="Viewed intake" if intake else "Viewed missing intake")
    return render_template("intake/record.html", record=record, intake=intake, sources=REFERRAL_SOURCES,
                           can_write=can_write_intake(current_user, record))


@intake_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def save_intake(record_id):
    record = _record_or_404(record_id)
    if not can_write_intake(current_user, record):
        audit_access_denied("Refused to change an intake", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        values = intake_service.validate(request.form)
        existing = intake_service.get(record.id)
        if existing is None:
            intake_service.create(current_user, record, values)
            flash("Intake recorded.", "success")
        else:
            changed = intake_service.update(current_user, existing, values)
            flash("Intake updated." if changed else "No changes to save.", "success" if changed else "info")
    except intake_service.IntakeError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("intake.intake_page", record_id=record.id))
