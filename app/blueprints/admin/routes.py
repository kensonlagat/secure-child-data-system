"""
Administrator Module (built alongside other sprints, primarily Sprint 2+).

Scope per proposal:
- Register users, assign roles
- Configure institution mode (School / Children's Home) + optional academic module
- Full audit log access
- Manage role permissions, deactivate accounts
"""
from datetime import date, datetime

from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash

from app import db
from app.middleware.rbac import require_role
from app.models.anomaly_alert import AnomalyAlert
from app.models.child_record import ChildRecord
from app.models.audit_log import AuditLogEntry
from app.models.legal_status_change_request import LegalStatusChangeRequest
from app.models.otp_event import OTPEvent
from app.models.user import User
from app.services.audit_service import log_action
from app.services.otp_service import generate_otp, verify_otp
from sqlalchemy import func

admin_bp = Blueprint("admin", __name__, template_folder="../../templates")


def _new_anomaly_alert_count():
    """Return the number of anomaly alerts still awaiting review."""
    return AnomalyAlert.query.filter_by(status="new").count()


def _latest_record_deletion_otp(record_id):
    """Return the latest OTP event for the current user and record deletion flow."""
    return (
        OTPEvent.query.filter_by(
            user_id=current_user.id,
            action_context="record_deletion",
            target_record_id=record_id,
        )
        .order_by(OTPEvent.id.desc())
        .first()
    )


@admin_bp.route("/dashboard")
@login_required
@require_role("administrator")
def dashboard():
    record_counts = (
        db.session.query(
            ChildRecord.institution_mode,
            func.count(ChildRecord.id),
        )
        .group_by(ChildRecord.institution_mode)
        .order_by(ChildRecord.institution_mode)
        .all()
    )
    pending_legal_status_requests = LegalStatusChangeRequest.query.filter(
        LegalStatusChangeRequest.status.in_(["pending_otp", "pending_approval"])
    ).count()
    recent_audit_rows = (
        db.session.query(AuditLogEntry, User.full_name.label("user_full_name"))
        .join(User, AuditLogEntry.user_id == User.id)
        .order_by(AuditLogEntry.timestamp.desc(), AuditLogEntry.id.desc())
        .limit(10)
        .all()
    )
    new_anomaly_alert_count = _new_anomaly_alert_count()

    return render_template(
        "admin/dashboard.html",
        record_counts=record_counts,
        pending_legal_status_requests=pending_legal_status_requests,
        recent_audit_rows=recent_audit_rows,
        new_anomaly_alert_count=new_anomaly_alert_count,
    )


@admin_bp.route("/anomaly-alerts")
@login_required
@require_role("administrator")
def anomaly_alerts():
    """Render anomaly alerts ordered from most to least anomalous."""
    alert_rows = (
        db.session.query(
            AnomalyAlert,
            AuditLogEntry,
            User.full_name.label("user_full_name"),
        )
        .join(AuditLogEntry, AnomalyAlert.audit_log_entry_id == AuditLogEntry.id)
        .join(User, AuditLogEntry.user_id == User.id)
        .order_by(AnomalyAlert.anomaly_score.asc(), AnomalyAlert.id.asc())
        .all()
    )

    return render_template(
        "admin/anomaly_alerts.html",
        alert_rows=alert_rows,
        new_anomaly_alert_count=_new_anomaly_alert_count(),
    )


@admin_bp.route("/anomaly-alerts/<int:alert_id>/mark-reviewed", methods=["POST"])
@login_required
@require_role("administrator")
def mark_anomaly_alert_reviewed(alert_id):
    """Mark an anomaly alert as reviewed and audit the action."""
    alert = db.session.get(AnomalyAlert, alert_id)
    if alert is None:
        return jsonify({"error": "Anomaly alert not found."}), 404

    alert.status = "reviewed"
    log_action(
        user_id=current_user.id,
        action="anomaly_alert_reviewed",
        target_record_type="anomaly_alert",
        target_record_id=alert.id,
        details=f"Reviewed anomaly alert {alert.id}",
    )
    return jsonify({"message": "Alert marked as reviewed.", "status": alert.status})


@admin_bp.route("/anomaly-alerts/<int:alert_id>/dismiss", methods=["POST"])
@login_required
@require_role("administrator")
def dismiss_anomaly_alert(alert_id):
    """Dismiss an anomaly alert and audit the action."""
    alert = db.session.get(AnomalyAlert, alert_id)
    if alert is None:
        return jsonify({"error": "Anomaly alert not found."}), 404

    alert.status = "dismissed"
    log_action(
        user_id=current_user.id,
        action="anomaly_alert_dismissed",
        target_record_type="anomaly_alert",
        target_record_id=alert.id,
        details=f"Dismissed anomaly alert {alert.id}",
    )
    return jsonify({"message": "Alert dismissed.", "status": alert.status})


@admin_bp.route("/records/new")
@login_required
@require_role("administrator")
def create_record_form():
    """Render the record creation form for administrators."""
    return render_template(
        "admin/create_record.html",
        new_anomaly_alert_count=_new_anomaly_alert_count(),
    )


@admin_bp.route("/records", methods=["POST"])
@login_required
@require_role("administrator")
def create_record():
    """Create a new child record for school or children's home enrollment."""
    payload = request.get_json(silent=True) if request.is_json else request.form
    payload = payload or {}

    full_name = payload.get("full_name")
    date_of_birth = payload.get("date_of_birth")
    institution_mode = payload.get("institution_mode")

    if not full_name or not date_of_birth or institution_mode not in {"school", "childrens_home"}:
        error_payload = {
            "error": "full_name, date_of_birth, and a valid institution_mode are required.",
        }
        if request.is_json:
            return jsonify(error_payload), 400
        return render_template(
            "admin/create_record.html",
            error=error_payload["error"],
            new_anomaly_alert_count=_new_anomaly_alert_count(),
        ), 400

    try:
        parsed_date_of_birth = date.fromisoformat(date_of_birth)
    except (TypeError, ValueError):
        if request.is_json:
            return jsonify({"error": "date_of_birth must be a valid ISO format date string."}), 400
        return render_template(
            "admin/create_record.html",
            error="date_of_birth must be a valid ISO format date string.",
            new_anomaly_alert_count=_new_anomaly_alert_count(),
        ), 400

    record = ChildRecord()
    record.full_name = full_name
    record.date_of_birth = parsed_date_of_birth
    record.institution_mode = institution_mode

    if institution_mode == "school":
        record.guardian_contact = payload.get("guardian_contact")
        record.class_assigned = payload.get("class_assigned")
    else:
        # Legal status changes must use the dedicated two-person approval workflow,
        # so enrollment always starts with a fixed safe default instead of caller input.
        record.legal_status = "in_state_care"

        caseload_worker_id = payload.get("caseload_worker_id")
        if caseload_worker_id is not None:
            try:
                caseload_worker_id = int(caseload_worker_id)
            except (TypeError, ValueError):
                if request.is_json:
                    return jsonify({"error": "caseload_worker_id must be an integer."}), 400
                return render_template(
                    "admin/create_record.html",
                    error="caseload_worker_id must be an integer.",
                    new_anomaly_alert_count=_new_anomaly_alert_count(),
                ), 400

            caseload_worker = db.session.get(User, caseload_worker_id)
            if caseload_worker is None or getattr(caseload_worker.role, "name", None) != "social_worker":
                if request.is_json:
                    return jsonify({"error": "caseload_worker_id must reference an existing social_worker."}), 400
                return render_template(
                    "admin/create_record.html",
                    error="caseload_worker_id must reference an existing social_worker.",
                    new_anomaly_alert_count=_new_anomaly_alert_count(),
                ), 400

            record.caseload_worker_id = caseload_worker_id

    db.session.add(record)
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="create_record",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Created child record with institution_mode={institution_mode}",
    )

    if request.is_json:
        return jsonify({"id": record.id, "institution_mode": record.institution_mode}), 201

    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/records/<int:record_id>/request-deletion", methods=["POST"])
@login_required
@require_role("administrator")
def request_record_deletion(record_id):
    """Generate an OTP for soft-deleting a child record."""
    record = db.session.get(ChildRecord, record_id)
    if record is None:
        return jsonify({"error": "Child record not found."}), 404

    if record.is_deleted:
        return jsonify({"error": "Child record has already been deleted."}), 400

    try:
        generate_otp(current_user, "record_deletion", target_record_id=record.id)
    except Exception:
        return jsonify({"error": "Unable to generate deletion OTP."}), 500

    log_action(
        user_id=current_user.id,
        action="record_deletion_requested",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Requested deletion for child record institution_mode={record.institution_mode}",
    )

    return jsonify({"message": "Deletion OTP sent."}), 201


@admin_bp.route("/records/<int:record_id>/confirm-deletion", methods=["POST"])
@login_required
@require_role("administrator")
def confirm_record_deletion(record_id):
    """Verify the deletion OTP and soft-delete the child record."""
    record = db.session.get(ChildRecord, record_id)
    if record is None:
        return jsonify({"error": "Child record not found."}), 404

    if record.is_deleted:
        return jsonify({"error": "Child record has already been deleted."}), 400

    otp_event = _latest_record_deletion_otp(record.id)
    if otp_event is None or otp_event.user_id != current_user.id:
        log_action(
            user_id=current_user.id,
            action="record_deletion_otp_failed",
            target_record_type="child_record",
            target_record_id=record.id,
            details="No matching deletion OTP was found for the current administrator.",
        )
        return jsonify({"error": "Deletion OTP verification failed."}), 400

    payload = request.get_json(silent=True) or {}
    otp_code = payload.get("otp_code")
    if not otp_code:
        log_action(
            user_id=current_user.id,
            action="record_deletion_otp_failed",
            target_record_type="child_record",
            target_record_id=record.id,
            details="Missing otp_code for record deletion verification.",
        )
        return jsonify({"error": "Deletion OTP verification failed."}), 400

    if not verify_otp(otp_event, otp_code):
        log_action(
            user_id=current_user.id,
            action="record_deletion_otp_failed",
            target_record_type="child_record",
            target_record_id=record.id,
            details="Deletion OTP verification failed.",
        )
        return jsonify({"error": "Deletion OTP verification failed."}), 400

    record.is_deleted = True
    record.deleted_at = datetime.utcnow()
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="record_deleted",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Deleted child record institution_mode={record.institution_mode}",
    )

    return jsonify({"message": "Child record deleted successfully.", "status": "deleted"})
