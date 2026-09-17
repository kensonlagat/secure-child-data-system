"""
School Mode Module (Sprint 3).

Scope per proposal:
- Teachers: academic records for their assigned class only
- School Nurse: medical records only
- Admin staff: fee records + general info
- Parents: SMS notification on record access/modification
"""
from flask import Blueprint, abort, jsonify, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.models.child_record import ChildRecord
from app.services.access_service import (
    can_access_record,
    get_accessible_records,
    get_visible_fields,
    get_writable_fields,
)
from app.services.audit_service import log_action
from app.services.sms_service import send_sms

school_bp = Blueprint("school_mode", __name__, template_folder="../../templates")


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
            details="Denied child record access in school mode",
        )
        abort(403)
    return record


@school_bp.route("/records")
@login_required
def records():
    """Return the current user's scoped school-mode child records."""
    visible_fields = get_visible_fields(current_user)
    records_query = get_accessible_records(current_user).filter(
        ChildRecord.institution_mode == "school"
    )
    record_entries = []
    for record in records_query.all():
        record_entries.append(
            {
                "record": record,
                "values": _serialize_record(record, visible_fields),
                "writable_fields": get_writable_fields(current_user, record),
            }
        )

    log_action(
        user_id=current_user.id,
        action="view_records",
        target_record_type="child_record",
        details="Viewed scoped school mode child records",
    )

    wants_html = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if wants_html:
        return render_template(
            "records/list.html",
            page_title="School Records",
            page_heading="School records",
            page_subtitle="Your scoped school-mode child records.",
            visible_fields=visible_fields,
            record_entries=record_entries,
            edit_url_builder=lambda record_id: url_for("school_mode.edit_record", record_id=record_id),
        )

    return jsonify([entry["values"] for entry in record_entries])


@school_bp.route("/records/<int:record_id>/edit")
@login_required
def edit_record(record_id):
    """Render a focused edit form for writable school-mode fields."""
    record = require_record_access(record_id)
    writable_fields = get_writable_fields(current_user, record)
    if not writable_fields:
        abort(403)

    field_meta = []
    for field_name in writable_fields:
        field_type = "text"
        if field_name.endswith("_id"):
            field_type = "number"
        elif field_name == "date_of_birth":
            field_type = "date"
        field_value = getattr(record, field_name)
        if hasattr(field_value, "isoformat"):
            field_value = field_value.isoformat()
        field_meta.append(
            {
                "name": field_name,
                "label": field_name.replace("_", " ").title(),
                "type": field_type,
                "value": field_value or "",
            }
        )

    return render_template(
        "records/edit.html",
        page_title="Edit School Record",
        page_heading=f"Edit {record.full_name}",
        page_subtitle="Update only the fields your role can write.",
        record=record,
        field_meta=field_meta,
        patch_url=url_for("school_mode.update_record", record_id=record.id),
        back_url=url_for("school_mode.records"),
    )


@school_bp.route("/records/<int:record_id>", methods=["PATCH"])
@login_required
def update_record(record_id):
    """Update only the fields this user may write on a school-mode record."""
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

    guardian_contact = getattr(record, "guardian_contact", None)
    if guardian_contact and record.institution_mode == "school":
        try:
            send_sms(
                guardian_contact,
                "A record update was made for your child. Contact the school for details.",
            )
        except Exception:
            log_action(
                user_id=current_user.id,
                action="sms_notification_failed",
                target_record_type="child_record",
                target_record_id=record_id,
                details="Failed to send guardian SMS notification after record update.",
            )

    return jsonify({"message": "Record updated successfully.", "updated_fields": changed_fields})
