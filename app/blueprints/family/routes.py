"""Family contact and visits (#58). The assigned social worker writes; the home manager
reads. Out of scope is 404 (audited, bounded)."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.models.family import TRACING_STATUSES, VISITOR_RELATIONSHIPS
from app.services import family_service as family
from app.services.access_service import can_read_family, can_write_family, get_accessible_records
from app.services.audit_service import log_action

family_bp = Blueprint("family", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not can_read_family(current_user, record):
        audit_access_denied("Denied family contact access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


def _post(record_id, action):
    record = _record_or_404(record_id)
    if not can_write_family(current_user, record):
        audit_access_denied("Refused to change family contact", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        action(record)
        flash("Saved.", "success")
    except family.FamilyError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("family.family_page", record_id=record.id))


@family_bp.route("/records/<int:record_id>")
@login_required
def family_page(record_id):
    record = _record_or_404(record_id)
    entries = family.visits(record.id)
    log_action(user_id=current_user.id, action="family_visits_viewed", target_record_type="child_record",
               target_record_id=record.id, details=f"Viewed {len(entries)} visit(s)")
    return render_template("family/visits.html", record=record, visits=entries, tracing=family.tracing(record.id),
                           can_write=can_write_family(current_user, record), relationships=VISITOR_RELATIONSHIPS,
                           statuses=TRACING_STATUSES)


@family_bp.route("/records/<int:record_id>/visits", methods=["POST"])
@login_required
def add_visit(record_id):
    return _post(record_id, lambda record: family.add_visit(current_user, record, request.form))


@family_bp.route("/records/<int:record_id>/tracing", methods=["POST"])
@login_required
def set_tracing(record_id):
    return _post(record_id, lambda record: family.set_tracing(current_user, record, request.form))
