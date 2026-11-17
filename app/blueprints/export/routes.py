"""OTP-protected export (#65). Administrators only. A request fixes the export, a code is sent
to the requester, and only that code (bound to that request) releases the CSV, once."""

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied, require_role
from app.models.export import ExportRequest
from app.models.otp_event import OTPEvent
from app.models.school_class import SchoolClass
from app.services import export_service as export
from app.services.access_service import get_visible_fields
from app.services.audit_service import log_action
from app.services.otp_service import generate_otp, verify_otp

export_bp = Blueprint("export", __name__, template_folder="../../templates")


@export_bp.route("/")
@login_required
@require_role("administrator")
def export_page():
    return render_template("export/request.html", columns=get_visible_fields(current_user),
                           classes=SchoolClass.query.filter_by(is_active=True).order_by(SchoolClass.name).all())


@export_bp.route("/request", methods=["POST"])
@login_required
@require_role("administrator")
def request_export():
    try:
        target_id = int(request.form.get("target_id") or 0)
        row = export.create_request(current_user, request.form.get("export_type"), target_id,
                                    request.form.getlist("columns"))
        generate_otp(current_user, export.otp_context(row), target_record_id=row.id)
    except (ValueError, export.ExportError) as error:
        db.session.rollback()
        flash(str(error) if isinstance(error, export.ExportError) else "Enter a valid record or class.", "error")
        return redirect(url_for("export.export_page"))
    except Exception:
        db.session.rollback()
        flash("The code could not be sent, so nothing will be exported.", "error")
        return redirect(url_for("export.export_page"))
    return redirect(url_for("export.confirm_page", request_id=row.id))


def _own_pending_or_404(request_id):
    row = db.session.get(ExportRequest, request_id)
    if row is None or row.user_id != current_user.id or row.status != "pending":
        audit_access_denied("Export request unavailable", status_code=404, target_record_type="export_request",
                            target_record_id=request_id)
        abort(404)
    return row


@export_bp.route("/<int:request_id>/confirm", methods=["GET"])
@login_required
@require_role("administrator")
def confirm_page(request_id):
    return render_template("export/confirm.html", row=_own_pending_or_404(request_id))


@export_bp.route("/<int:request_id>/confirm", methods=["POST"])
@login_required
@require_role("administrator")
def confirm(request_id):
    row = _own_pending_or_404(request_id)
    code = (request.form.get("otp_code") or "").strip()
    otp = (OTPEvent.query.filter_by(user_id=current_user.id, action_context=export.otp_context(row),
                                    target_record_id=row.id)
           .order_by(OTPEvent.id.desc()).first())
    if not (otp and otp.user_id == current_user.id and code and verify_otp(otp, code)):
        log_action(user_id=current_user.id, action="export_otp_failed", target_record_type="export_request",
                   target_record_id=row.id, details="Export code verification failed")
        flash("The code is not valid. Request a new export if needed.", "error")
        return redirect(url_for("export.confirm_page", request_id=row.id))
    try:
        text, row_count = export.build_csv(current_user, row)
    except export.ExportError as error:
        flash(str(error), "error")
        return redirect(url_for("export.export_page"))
    export.complete(current_user, row, row_count)
    return Response(text, mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="export-{row.id}.csv"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
