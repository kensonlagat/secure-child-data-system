"""Clinic visit log (#52). Clinical officers record and read for school children;
administrators read. Everyone else, and anything out of scope, gets 404 (audited, bounded)."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.services import clinic_service
from app.services.access_service import can_read_clinic, can_record_clinic, get_accessible_records
from app.services.audit_service import log_action

clinic_bp = Blueprint("clinic", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not can_read_clinic(current_user, record):
        audit_access_denied("Denied clinic log access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


@clinic_bp.route("/records/<int:record_id>")
@login_required
def visits(record_id):
    record = _record_or_404(record_id)
    entries = clinic_service.visits(record.id)
    log_action(user_id=current_user.id, action="clinic_visits_viewed", target_record_type="child_record",
               target_record_id=record.id, details=f"Viewed {len(entries)} clinic visit(s)")
    return render_template("clinic/visits.html", record=record, visits=entries,
                           can_record=can_record_clinic(current_user, record))


@clinic_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def add_visit(record_id):
    record = _record_or_404(record_id)
    if not can_record_clinic(current_user, record):
        audit_access_denied("Refused to record a clinic visit", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        clinic_service.record(current_user, record, clinic_service.validate(request.form))
        flash("Visit recorded.", "success")
    except clinic_service.ClinicError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("clinic.visits", record_id=record.id))
