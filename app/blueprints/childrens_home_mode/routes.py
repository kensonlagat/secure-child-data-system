"""
Children's Home Mode Module (Sprint 4).

Scope per proposal:
- Social workers: welfare records for their caseload only
- Legal officers: legal status, court dates, guardianship
- Legal status changes require two-person approval before saving
- Optional academic module for homes running internal schools
"""
from datetime import datetime

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import require_role
from app.models.child_record import ChildRecord
from app.models.legal_status_change_request import LegalStatusChangeRequest, VALID_LEGAL_STATUSES
from app.services.access_service import (
    can_access_record,
    get_accessible_records,
    get_visible_fields,
    get_writable_fields,
)
from app.services.audit_service import log_action
from app.services.otp_service import generate_otp, verify_otp
from app.services.sms_service import send_sms

home_bp = Blueprint("childrens_home_mode", __name__, template_folder="../../templates")


def _serialize_record(record, visible_fields):
    """Serialize a child record using only the explicitly visible field list."""
    return {field_name: getattr(record, field_name) for field_name in visible_fields}


def require_record_access(record_id):
    """Return a record only when the current user is allowed to access it."""
    record = db.session.get(ChildRecord, record_id)
    if record is None:
        abort(404)
    if not can_access_record(current_user, record):
        log_action(
            user_id=current_user.id,
            action="access_denied",
            target_record_type="child_record",
            target_record_id=record_id,
            details="Denied child record access in children's home mode",
        )
        abort(403)
    return record


def _load_change_request_or_404(change_request_id):
    """Load a legal status change request or return a 404 response."""
    change_request = db.session.get(LegalStatusChangeRequest, change_request_id)
    if change_request is None:
        abort(404)
    return change_request


def _log_and_abort(status_code, action, details, target_record_id=None):
    """Write an audit row for a denied or failed state transition, then abort."""
    log_action(
        user_id=current_user.id,
        action=action,
        target_record_type="child_record",
        target_record_id=target_record_id,
        details=details,
    )
    abort(status_code)


@home_bp.route("/records")
@login_required
def records():
    """Return the current user's scoped children's-home child records."""
    visible_fields = get_visible_fields(current_user)
    records_query = get_accessible_records(current_user).filter(
        ChildRecord.institution_mode == "childrens_home"
    )
    serialized_records = [
        _serialize_record(record, visible_fields) for record in records_query.all()
    ]

    log_action(
        user_id=current_user.id,
        action="view_records",
        target_record_type="child_record",
        details="Viewed scoped children's home child records",
    )
    return jsonify(serialized_records)


@home_bp.route("/records/<int:record_id>", methods=["PATCH"])
@login_required
def update_record(record_id):
    """Update only the fields this user may write on a children's-home record."""
    record = require_record_access(record_id)
    writable_fields = get_writable_fields(current_user, record)
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict) or not payload:
        return jsonify({"error": "Request JSON must include at least one updatable field."}), 400

    rejected_fields = sorted([field_name for field_name in payload.keys() if field_name not in writable_fields])
    if rejected_fields:
        return (
            jsonify({
                "error": "Request contained field(s) this role cannot update.",
                "rejected_fields": rejected_fields,
            }),
            400,
        )

    valid_updates = {field_name: payload[field_name] for field_name in payload.keys() if field_name in writable_fields}
    if not valid_updates:
        return jsonify({"error": "Request contained no valid writable fields."}), 400

    changed_fields = []
    for field_name, new_value in valid_updates.items():
        if getattr(record, field_name) != new_value:
            setattr(record, field_name, new_value)
            changed_fields.append(field_name)

    if not changed_fields:
        return jsonify({"error": "No changes were applied."}), 400

    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="update_record",
        target_record_type="child_record",
        target_record_id=record_id,
        details=f"Updated fields: {', '.join(changed_fields)}",
    )

    return jsonify({"message": "Record updated successfully.", "updated_fields": changed_fields})


@home_bp.route("/legal-status/<int:record_id>/request-change", methods=["POST"])
@login_required
@require_role("legal_officer", "administrator")
def request_legal_status_change(record_id):
    """Create a legal status change request and send the requester OTP."""
    record = require_record_access(record_id)
    payload = request.get_json(silent=True) or {}
    requested_status = payload.get("requested_status")

    if not requested_status:
        _log_and_abort(
            400,
            "legal_status_change_request_failed",
            "Missing requested_status in legal status change request.",
            target_record_id=record_id,
        )

    if requested_status not in VALID_LEGAL_STATUSES:
        _log_and_abort(
            400,
            "legal_status_change_request_failed",
            "Requested legal status is not recognized.",
            target_record_id=record_id,
        )

    try:
        otp_event = generate_otp(current_user, "legal_status_change", target_record_id=record.id)
    except Exception:
        _log_and_abort(
            500,
            "legal_status_change_request_failed",
            "Failed to generate requester OTP for legal status change.",
            target_record_id=record.id,
        )

    change_request = LegalStatusChangeRequest()
    change_request.child_record_id = record.id
    change_request.requested_by_user_id = current_user.id
    change_request.current_status = record.legal_status or ""
    change_request.requested_status = requested_status
    change_request.status = "pending_otp"
    change_request.requester_otp_event_id = otp_event.id

    db.session.add(change_request)
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="legal_status_change_requested",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Requested legal status change to {requested_status}",
    )

    return jsonify({"change_request_id": change_request.id}), 201


@home_bp.route("/legal-status/confirm-request/<int:change_request_id>", methods=["POST"])
@login_required
@require_role("legal_officer", "administrator")
def confirm_legal_status_request(change_request_id):
    """Verify the requester OTP and move the change request to approval pending."""
    change_request = _load_change_request_or_404(change_request_id)
    require_record_access(change_request.child_record_id)

    if current_user.id != change_request.requester_otp_event.user_id:
        _log_and_abort(
            403,
            "legal_status_change_otp_failed",
            "OTP confirmation must be performed by the original requester.",
            target_record_id=change_request.child_record_id,
        )

    payload = request.get_json(silent=True) or {}
    otp_code = payload.get("otp_code")
    if not otp_code:
        _log_and_abort(
            400,
            "legal_status_change_otp_failed",
            "Missing otp_code for requester OTP verification.",
            target_record_id=change_request.child_record_id,
        )

    if change_request.status != "pending_otp" or change_request.requester_otp_event is None:
        _log_and_abort(
            400,
            "legal_status_change_otp_failed",
            "Legal status change request is not awaiting requester OTP verification.",
            target_record_id=change_request.child_record_id,
        )

    if not verify_otp(change_request.requester_otp_event, otp_code):
        _log_and_abort(
            400,
            "legal_status_change_otp_failed",
            "Requester OTP verification failed for legal status change.",
            target_record_id=change_request.child_record_id,
        )

    change_request.status = "pending_approval"
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="legal_status_change_otp_verified",
        target_record_type="child_record",
        target_record_id=change_request.child_record_id,
        details=f"Requester OTP verified for legal status change request {change_request.id}",
    )

    return jsonify({"change_request_id": change_request.id, "status": change_request.status})


@home_bp.route("/legal-status/approve/<int:change_request_id>", methods=["POST"])
@login_required
@require_role("legal_officer", "administrator")
def request_legal_status_approval(change_request_id):
    """Send the approver OTP after enforcing the two-person rule."""
    change_request = _load_change_request_or_404(change_request_id)
    record = require_record_access(change_request.child_record_id)

    if change_request.status != "pending_approval":
        _log_and_abort(
            400,
            "legal_status_change_approval_failed",
            "Legal status change request is not awaiting approver OTP generation.",
            target_record_id=record.id,
        )

    if current_user.id == change_request.requested_by_user_id:
        _log_and_abort(
            403,
            "legal_status_approval_denied_same_user",
            "Requester cannot also act as the approver for the same legal status change.",
            target_record_id=record.id,
        )

    try:
        otp_event = generate_otp(current_user, "legal_status_change_approval", target_record_id=record.id)
    except Exception:
        _log_and_abort(
            500,
            "legal_status_change_approval_failed",
            "Failed to generate approver OTP for legal status change.",
            target_record_id=record.id,
        )

    change_request.approver_otp_event_id = otp_event.id
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="legal_status_change_approval_requested",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Approver OTP generated for legal status change request {change_request.id}",
    )

    return jsonify(
        {
            "message": "Approval OTP sent. Confirm approval with the OTP to complete the change.",
            "change_request_id": change_request.id,
            "status": change_request.status,
        }
    )


@home_bp.route("/legal-status/confirm-approval/<int:change_request_id>", methods=["POST"])
@login_required
@require_role("legal_officer", "administrator")
def confirm_legal_status_approval(change_request_id):
    """Verify the approver OTP and apply the requested legal status."""
    change_request = _load_change_request_or_404(change_request_id)
    record = require_record_access(change_request.child_record_id)
    old_status = record.legal_status

    if current_user.id != change_request.approver_otp_event.user_id:
        _log_and_abort(
            403,
            "legal_status_change_approval_otp_failed",
            "OTP confirmation must be performed by the original approver.",
            target_record_id=record.id,
        )

    payload = request.get_json(silent=True) or {}
    otp_code = payload.get("otp_code")
    if not otp_code:
        _log_and_abort(
            400,
            "legal_status_change_approval_otp_failed",
            "Missing otp_code for approver OTP verification.",
            target_record_id=record.id,
        )

    if change_request.status != "pending_approval" or change_request.approver_otp_event is None:
        _log_and_abort(
            400,
            "legal_status_change_approval_otp_failed",
            "Legal status change request is not awaiting approver OTP verification.",
            target_record_id=record.id,
        )

    if not verify_otp(change_request.approver_otp_event, otp_code):
        _log_and_abort(
            400,
            "legal_status_change_approval_otp_failed",
            "Approver OTP verification failed for legal status change.",
            target_record_id=record.id,
        )

    record.legal_status = change_request.requested_status
    change_request.status = "approved"
    change_request.resolved_at = datetime.utcnow()
    change_request.approved_by_user_id = current_user.id
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="legal_status_change_approved",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Legal status changed from {old_status} to {change_request.requested_status}",
    )

    return jsonify({"change_request_id": change_request.id, "status": change_request.status})


@home_bp.route("/legal-status/reject/<int:change_request_id>", methods=["POST"])
@login_required
@require_role("legal_officer", "administrator")
def reject_legal_status_change(change_request_id):
    """Reject a pending legal status change request with audit logging."""
    change_request = _load_change_request_or_404(change_request_id)
    record = require_record_access(change_request.child_record_id)

    if current_user.id == change_request.requested_by_user_id:
        _log_and_abort(
            403,
            "legal_status_rejection_denied_same_user",
            "Requester cannot also reject the same legal status change request.",
            target_record_id=record.id,
        )

    if change_request.status not in {"pending_otp", "pending_approval"}:
        _log_and_abort(
            400,
            "legal_status_change_rejection_failed",
            "Legal status change request is not in a rejectable state.",
            target_record_id=record.id,
        )

    change_request.status = "rejected"
    change_request.resolved_at = datetime.utcnow()
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="legal_status_change_rejected",
        target_record_type="child_record",
        target_record_id=record.id,
        details=f"Legal status change request {change_request.id} rejected",
    )

    return jsonify({"change_request_id": change_request.id, "status": change_request.status})
