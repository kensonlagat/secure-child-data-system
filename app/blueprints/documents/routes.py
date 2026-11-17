"""Encrypted document storage (#66). Every request re-checks record access and the
type-and-role allowlist; out of scope is 404 (audited, bounded). Downloads are forced
attachments with nosniff, no-store and CSP sandbox, and every download is audited."""

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.models.document import DOCUMENT_TYPES, Document
from app.models.otp_event import OTPEvent
from app.services import document_service as documents
from app.services.access_service import (
    can_delete_document,
    can_upload_document,
    can_view_document,
    get_accessible_records,
)
from app.services.audit_service import log_action
from app.services.otp_service import generate_otp, verify_otp

documents_bp = Blueprint("documents", __name__, template_folder="../../templates")
DELETE_CONTEXT = "document_delete"


def _deny(details, record_id):
    audit_access_denied(details, status_code=404, target_record_type="child_record", target_record_id=record_id,
                        actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
    abort(404)


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not any(can_view_document(current_user, record, t) or can_upload_document(current_user, record, t)
                                 for t in DOCUMENT_TYPES):
        _deny("Denied document access", record_id)
    return record


def _document_or_404(document_id):
    document = db.session.get(Document, document_id)
    record = (get_accessible_records(current_user).filter(ChildRecord.id == document.child_record_id).first()
              if document is not None and not document.is_deleted else None)
    if record is None or not can_view_document(current_user, record, document.document_type):
        _deny("Denied document download", document.child_record_id if document else document_id)
    return document, record


@documents_bp.route("/records/<int:record_id>")
@login_required
def document_list(record_id):
    record = _record_or_404(record_id)
    viewable = [t for t in DOCUMENT_TYPES if can_view_document(current_user, record, t)]
    entries = (Document.query.filter(Document.child_record_id == record.id, Document.is_deleted.is_(False),
                                     Document.document_type.in_(viewable)).order_by(Document.uploaded_at.desc()).all()
               if viewable else [])
    log_action(user_id=current_user.id, action="documents_listed", target_record_type="child_record",
               target_record_id=record.id, details=f"Listed {len(entries)} document(s)")
    return render_template("documents/list.html", record=record, documents=entries,
                           upload_types=[t for t in DOCUMENT_TYPES if can_upload_document(current_user, record, t)],
                           can_delete=can_delete_document(current_user))


@documents_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def upload(record_id):
    record = _record_or_404(record_id)
    document_type = (request.form.get("document_type") or "").strip()
    if document_type not in DOCUMENT_TYPES or not can_upload_document(current_user, record, document_type):
        audit_access_denied("Refused document upload", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    file = request.files.get("file")
    try:
        documents.store(current_user, record, document_type, file.filename if file else "",
                        file.read(documents.MAX_BYTES + 1) if file else b"")
        flash("Document uploaded and encrypted.", "success")
    except documents.DocumentError as error:
        db.session.rollback()
        log_action(user_id=current_user.id, action="document_upload_refused", target_record_type="child_record",
                   target_record_id=record.id, details=f"Refused {document_type}: {error.reason}")
        flash(str(error), "error")
    return redirect(url_for("documents.document_list", record_id=record.id))


@documents_bp.route("/<int:document_id>")
@login_required
def download(document_id):
    document, record = _document_or_404(document_id)
    try:
        data = documents.read(document)
    except documents.DocumentIntegrityError:
        log_action(user_id=current_user.id, action="document_integrity_failed", target_record_type="child_record",
                   target_record_id=record.id, details=f"Document {document.id} failed its integrity check")
        return render_template("documents/integrity_error.html", record=record), 409
    log_action(user_id=current_user.id, action="document_downloaded", target_record_type="child_record",
               target_record_id=record.id, details=f"Downloaded {document.document_type} document {document.id}")
    return Response(data, mimetype=document.content_type, headers={
        "Content-Disposition": f'attachment; filename="document-{document.id}.{documents.extension(document)}"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Content-Security-Policy": "sandbox"})


@documents_bp.route("/<int:document_id>/delete", methods=["POST"])
@login_required
def request_delete(document_id):
    document, record = _document_or_404(document_id)
    if not can_delete_document(current_user):
        audit_access_denied("Refused document deletion", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        generate_otp(current_user, DELETE_CONTEXT, target_record_id=document.id)
    except Exception:
        flash("The code could not be sent, so the document was not deleted.", "error")
        return redirect(url_for("documents.document_list", record_id=record.id))
    log_action(user_id=current_user.id, action="document_delete_requested", target_record_type="child_record",
               target_record_id=record.id, details=f"Requested deletion of document {document.id}")
    return render_template("documents/confirm_delete.html", document=document, record=record)


@documents_bp.route("/<int:document_id>/delete/confirm", methods=["POST"])
@login_required
def confirm_delete(document_id):
    document, record = _document_or_404(document_id)
    if not can_delete_document(current_user):
        abort(403)
    code = (request.form.get("otp_code") or "").strip()
    otp = (OTPEvent.query.filter_by(user_id=current_user.id, action_context=DELETE_CONTEXT, target_record_id=document.id)
           .order_by(OTPEvent.id.desc()).first())
    if not (otp and otp.user_id == current_user.id and code and verify_otp(otp, code)):
        log_action(user_id=current_user.id, action="document_delete_otp_failed", target_record_type="child_record",
                   target_record_id=record.id, details=f"Deletion code failed for document {document.id}")
        flash("The code is not valid.", "error")
        return redirect(url_for("documents.document_list", record_id=record.id))
    document.is_deleted, document.deleted_at = True, db.func.now()
    log_action(user_id=current_user.id, action="document_deleted", target_record_type="child_record",
               target_record_id=record.id, details=f"Deleted document {document.id} (soft)")
    flash("Document deleted.", "success")
    return redirect(url_for("documents.document_list", record_id=record.id))
