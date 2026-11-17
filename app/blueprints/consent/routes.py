"""Consent pages (#63). Records are fetched only through access_service (hard rule 2);
missing and forbidden records both answer 404, with the real reason audited (bounded)."""

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.models.consent import CONSENT_STATUSES, CONSENT_TYPES
from app.services import consent_service
from app.services.access_service import (
    can_record_consent,
    can_view_consent_details,
    can_view_consent_status,
    get_accessible_records,
)
from app.services.audit_service import log_action

consent_bp = Blueprint("consent", __name__, template_folder="../../templates")
TYPE_LABELS = {"photo": "Photos", "medical_treatment": "Medical treatment", "data_sharing": "Data sharing"}


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is not None and can_view_consent_status(current_user, record):
        return record
    exists = db.session.get(ChildRecord, record_id) is not None
    audit_access_denied(
        "Denied consent page access" if exists else "Consent page for a record that does not exist",
        status_code=404, target_record_type="child_record", target_record_id=record_id,
        action="access_denied" if exists else "record_not_found",
        bound_per_target=exists,
        actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"] if exists else None,
    )
    abort(404)


def _status_view(record):
    """Status for everyone with access: type, given or withdrawn, date. No guardian name."""
    return {consent_type: ({"status": entry.status, "effective_date": entry.effective_date.isoformat()}
                           if entry else None)
            for consent_type, entry in consent_service.current(record.id).items()}


def _wants_json():
    return request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json"


@consent_bp.route("/records/<int:record_id>", methods=["GET"])
@login_required
def consent_page(record_id):
    record = _record_or_404(record_id)
    details = can_view_consent_details(current_user, record)
    log_action(user_id=current_user.id, action="consent_viewed", target_record_type="child_record",
               target_record_id=record.id, details="Viewed consent " + ("history" if details else "status"))
    status = _status_view(record)
    if _wants_json():
        payload = {"status": status}
        if details:
            payload["history"] = [{"consent_type": e.consent_type, "status": e.status,
                                   "effective_date": e.effective_date.isoformat(), "guardian_name": e.guardian_name,
                                   "recorded_at": e.recorded_at.isoformat()} for e in consent_service.history(record.id)]
        return jsonify(payload)
    return render_template("consent/record.html", record=record, status=status, type_labels=TYPE_LABELS,
                           can_record=can_record_consent(current_user, record),
                           history=consent_service.history(record.id) if details else None,
                           consent_types=CONSENT_TYPES, consent_statuses=CONSENT_STATUSES)


@consent_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def record_consent(record_id):
    record = _record_or_404(record_id)
    if not can_record_consent(current_user, record):
        audit_access_denied("Refused to record consent", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    form = request.get_json(silent=True) if request.is_json else request.form
    try:
        values = consent_service.validate(form or {})
    except consent_service.ConsentError as error:
        if request.is_json:
            return jsonify({"error": str(error)}), 400
        flash(str(error), "error")
        return redirect(url_for("consent.consent_page", record_id=record.id))
    consent_service.record(current_user, record, *values)
    if request.is_json:
        return jsonify({"status": _status_view(record)}), 201
    flash("Consent recorded.", "success")
    return redirect(url_for("consent.consent_page", record_id=record.id))
