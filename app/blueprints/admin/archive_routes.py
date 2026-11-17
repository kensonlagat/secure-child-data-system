"""Leaving, transfer and archiving (#64). Administrator-only. Archiving never deletes: the
record becomes read-only and invisible to day-to-day roles; restoring brings it back.
Both are audited. Records come only from access_service (hard rule 2)."""

from datetime import date

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.blueprints.admin.routes import admin_bp
from app.middleware.rbac import audit_access_denied, require_role
from app.models.child_record import ChildRecord
from app.services.access_service import get_accessible_records, get_archived_records
from app.services.audit_service import log_action

LEAVE_REASONS = ("transferred", "completed", "reunified", "adopted", "aged_out", "other")


def _retain_until(record):
    years = current_app.config.get("RECORD_RETENTION_YEARS", 7)
    leave = record.leave_date or date.today()
    try:
        return leave.replace(year=leave.year + years)
    except ValueError:  # 29 February
        return leave.replace(year=leave.year + years, day=28)


@admin_bp.route("/archive")
@login_required
@require_role("administrator")
def archive_list():
    records = get_archived_records(current_user).order_by(ChildRecord.archived_at.desc()).all()
    log_action(user_id=current_user.id, action="archive_viewed", target_record_type="child_record",
               details=f"Viewed {len(records)} archived record(s)")
    return render_template("admin/archive/list.html", records=records, retain_until=_retain_until,
                           years=current_app.config.get("RECORD_RETENTION_YEARS", 7))


def _active_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None:
        audit_access_denied("Archive requested for an unavailable record", status_code=404,
                            target_record_type="child_record", target_record_id=record_id)
        abort(404)
    return record


@admin_bp.route("/records/<int:record_id>/archive", methods=["GET"])
@login_required
@require_role("administrator")
def archive_form(record_id):
    record = _active_or_404(record_id)
    return render_template("admin/archive/form.html", record=record, reasons=LEAVE_REASONS, today=date.today())


@admin_bp.route("/records/<int:record_id>/archive", methods=["POST"])
@login_required
@require_role("administrator")
def archive_record(record_id):
    record = _active_or_404(record_id)
    reason = (request.form.get("leave_reason") or "").strip()
    try:
        leave_date = date.fromisoformat((request.form.get("leave_date") or "").strip())
    except ValueError:
        leave_date = None
    if reason not in LEAVE_REASONS or leave_date is None or leave_date > date.today():
        flash("Choose a leave reason and a leave date that is not in the future.", "error")
        return redirect(url_for("admin.archive_form", record_id=record.id))
    # Archiving hides a record everywhere, including the home manager's open-alert list, so a
    # child who is still missing must never be archived: resolve the alert first.
    from app.services.missing_service import open_alert

    if open_alert(record.id) is not None:
        log_action(user_id=current_user.id, action="record_archive_refused", target_record_type="child_record",
                   target_record_id=record.id, details="Refused: the child has an open missing alert")
        flash("This child has an open missing alert. Resolve the alert before archiving the record.", "error")
        return redirect(url_for("admin.archive_form", record_id=record.id))
    record.is_archived, record.leave_reason, record.leave_date = True, reason, leave_date
    record.archived_by, record.archived_at = current_user.id, db.func.now()
    log_action(user_id=current_user.id, action="record_archived", target_record_type="child_record",
               target_record_id=record.id, details=f"Archived: {reason}, left {leave_date.isoformat()}")
    flash("Record archived. It is now read-only and only visible in the archive.", "success")
    return redirect(url_for("admin.archive_list"))


@admin_bp.route("/records/<int:record_id>/restore", methods=["POST"])
@login_required
@require_role("administrator")
def restore_record(record_id):
    record = get_archived_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None:
        audit_access_denied("Restore requested for a record that is not archived", status_code=404,
                            target_record_type="child_record", target_record_id=record_id)
        abort(404)
    record.is_archived = False
    log_action(user_id=current_user.id, action="record_restored", target_record_type="child_record",
               target_record_id=record.id, details="Restored from the archive")
    flash("Record restored.", "success")
    return redirect(url_for("admin.archive_list"))
