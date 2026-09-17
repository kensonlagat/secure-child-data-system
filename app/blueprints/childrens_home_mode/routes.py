"""
Children's Home Mode Module (Sprint 4).

Scope per proposal:
- Social workers: welfare records for their caseload only
- Legal officers: legal status, court dates, guardianship
- Legal status changes require two-person approval before saving
- Optional academic module for homes running internal schools
"""
from flask import Blueprint, abort, jsonify
from flask_login import current_user, login_required

from app import db
from app.models.child_record import ChildRecord
from app.services.access_service import (
    can_access_record,
    get_accessible_records,
    get_visible_fields,
)
from app.services.audit_service import log_action

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


@home_bp.route("/legal-status/<int:record_id>/request-change", methods=["POST"])
@login_required
def request_legal_status_change(record_id):
    """Reserve legal status changes for the future two-person approval workflow."""
    require_record_access(record_id)
    # TODO (Sprint 4): create a pending change requiring second approver + OTP
    return "Legal status change workflow placeholder"
