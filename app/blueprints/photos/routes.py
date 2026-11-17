"""Child photos (#87). The image is served only to roles allowed to see it, only for records
in their scope, and only when photo consent is given. It is embedded on the record page only,
never in lists. Views are audited, bounded per user and record."""

from flask import Blueprint, Response, abort, current_app, flash, redirect, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.services import photo_service
from app.services.access_service import can_upload_photo, can_view_photo, get_accessible_records
from app.services.audit_service import log_action
from app.services.document_service import DocumentError

photos_bp = Blueprint("photos", __name__, template_folder="../../templates")


def _record(record_id):
    return get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()


@photos_bp.route("/records/<int:record_id>")
@login_required
def photo(record_id):
    record = _record(record_id)
    current = photo_service.current(record.id) if record is not None else None
    if record is None or current is None or not can_view_photo(current_user, record):
        audit_access_denied("Photo unavailable", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    try:
        data = photo_service.read(current)
    except photo_service.PhotoIntegrityError:
        log_action(user_id=current_user.id, action="child_photo_integrity_failed", target_record_type="child_record",
                   target_record_id=record.id, details=f"Photo {current.id} failed its integrity check")
        abort(404)
    # Bounded: one view row per user and record per window, however often the page reloads.
    audit_access_denied("Viewed child photo", status_code=200, target_record_type="child_record",
                        target_record_id=record.id, action="child_photo_viewed")
    return Response(data, mimetype=current.content_type, headers={
        "Content-Disposition": "inline", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Content-Security-Policy": "sandbox"})


@photos_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def upload(record_id):
    record = _record(record_id)
    if record is None or not can_upload_photo(current_user, record):
        audit_access_denied("Refused photo upload", status_code=403, target_record_type="child_record",
                            target_record_id=record_id)
        abort(403)
    file = request.files.get("photo")
    try:
        photo_service.store(current_user, record, file.read(photo_service.MAX_PHOTO_BYTES + 1) if file else b"")
        flash("Photo uploaded.", "success")
    except DocumentError as error:
        db.session.rollback()
        # Like document_upload_refused: the reason category only, never the file or its name.
        log_action(user_id=current_user.id, action="child_photo_upload_refused", target_record_type="child_record",
                   target_record_id=record.id, details=f"Refused photo: {error.reason}")
        flash(str(error), "error")
    endpoint = "school_mode.edit_record" if record.institution_mode == "school" else "childrens_home_mode.edit_record"
    return redirect(url_for(endpoint, record_id=record.id))
