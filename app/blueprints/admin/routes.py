"""
Administrator Module (built alongside other sprints, primarily Sprint 2+).

Scope per proposal:
- Register users, assign roles
- Configure institution mode (School / Children's Home) + optional academic module
- Full audit log access
- Manage role permissions, deactivate accounts
"""
from datetime import date

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash

from app import db
from app.middleware.rbac import require_role
from app.models.child_record import ChildRecord
from app.models.user import User
from app.services.audit_service import log_action

admin_bp = Blueprint("admin", __name__, template_folder="../../templates")


@admin_bp.route("/dashboard")
def dashboard():
    # TODO: consolidate user management, audit log access, anomaly alerts
    return "Admin dashboard placeholder"


@admin_bp.route("/records", methods=["POST"])
@login_required
@require_role("administrator")
def create_record():
    """Create a new child record for school or children's home enrollment."""
    payload = request.get_json(silent=True) or {}

    full_name = payload.get("full_name")
    date_of_birth = payload.get("date_of_birth")
    institution_mode = payload.get("institution_mode")

    if not full_name or not date_of_birth or institution_mode not in {"school", "childrens_home"}:
        return (
            jsonify(
                {
                    "error": "full_name, date_of_birth, and a valid institution_mode are required.",
                }
            ),
            400,
        )

    try:
        parsed_date_of_birth = date.fromisoformat(date_of_birth)
    except (TypeError, ValueError):
        return jsonify({"error": "date_of_birth must be a valid ISO format date string."}), 400

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
                return jsonify({"error": "caseload_worker_id must be an integer."}), 400

            caseload_worker = db.session.get(User, caseload_worker_id)
            if caseload_worker is None or getattr(caseload_worker.role, "name", None) != "social_worker":
                return jsonify({"error": "caseload_worker_id must reference an existing social_worker."}), 400

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

    return jsonify({"id": record.id, "institution_mode": record.institution_mode}), 201
