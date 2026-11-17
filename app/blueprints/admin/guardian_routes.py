"""Guardian links (#67), administrator only. A link starts pending and gives no access until the
administrator has checked the parent's identity offline and confirmed with an OTP sent to their
own phone, bound to that link. Only the TYPE of identity document is recorded, never a number."""

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.blueprints.admin.routes import admin_bp
from app.middleware.rbac import audit_access_denied, require_role
from app.models.child_record import ChildRecord
from app.models.guardian_link import IDENTITY_DOCUMENT_TYPES, RELATIONSHIPS, GuardianLink
from app.services import parent_service
from app.services.access_service import get_accessible_records

FORM_FIELDS = ("child_record_id", "phone", "full_name", "relationship", "identity_document_type")


def _school_records():
    return get_accessible_records(current_user).filter(ChildRecord.institution_mode == "school")


def _link_or_404(link_id):
    link = db.session.get(GuardianLink, link_id)
    record = (_school_records().filter(ChildRecord.id == link.child_record_id).first()
              if link is not None else None)
    if record is None:
        audit_access_denied("Denied guardian link access", status_code=404, target_record_type="guardian_link",
                            target_record_id=link_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return link, record


@admin_bp.route("/guardian-links", methods=["GET"])
@login_required
@require_role("administrator")
def guardian_links():
    records = _school_records()
    links = parent_service.links_for_admin(records)
    names = {record.id: record.full_name for record in
             records.filter(ChildRecord.id.in_({link.child_record_id for link in links})).all()} if links else {}
    return render_template("admin/guardian_links/list.html", links=links, names=names,
                           children=records.order_by(ChildRecord.id).all(), relationships=RELATIONSHIPS,
                           document_types=IDENTITY_DOCUMENT_TYPES, verifying=request.args.get("verify", type=int))


@admin_bp.route("/guardian-links", methods=["POST"])
@login_required
@require_role("administrator")
def create_guardian_link():
    form = {name: (request.form.get(name) or "").strip() for name in FORM_FIELDS}  # allowlist
    record = None
    if form["child_record_id"].isdigit():
        record = _school_records().filter(ChildRecord.id == int(form["child_record_id"])).first()
    try:
        parent_service.create_link(current_user, record, form["phone"], form["full_name"], form["relationship"],
                                   form["identity_document_type"])
        flash("Link created. It gives no access until you verify it.", "success")
    except parent_service.LinkError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("admin.guardian_links"))


@admin_bp.route("/guardian-links/<int:link_id>/request-code", methods=["POST"])
@login_required
@require_role("administrator")
def request_guardian_link_code(link_id):
    link, _ = _link_or_404(link_id)
    try:
        parent_service.request_link_verification(current_user, link)
        flash("We sent a code to your phone. Enter it to activate the link.", "info")
    except parent_service.LinkError as error:
        flash(str(error), "error")
        return redirect(url_for("admin.guardian_links"))
    except Exception:  # noqa: BLE001 - SMS failure: no 500
        db.session.rollback()
        flash("We couldn't send the code. Try again in a moment.", "error")
        return redirect(url_for("admin.guardian_links"))
    return redirect(url_for("admin.guardian_links", verify=link.id))


@admin_bp.route("/guardian-links/<int:link_id>/verify", methods=["POST"])
@login_required
@require_role("administrator")
def verify_guardian_link(link_id):
    link, _ = _link_or_404(link_id)
    try:
        parent_service.verify_link(current_user, link, request.form.get("code"))
        flash("Link verified. The parent can now sign in.", "success")
    except parent_service.LinkError as error:
        flash(str(error), "error")
    return redirect(url_for("admin.guardian_links"))


@admin_bp.route("/guardian-links/<int:link_id>/revoke", methods=["POST"])
@login_required
@require_role("administrator")
def revoke_guardian_link(link_id):
    link, _ = _link_or_404(link_id)
    try:
        parent_service.revoke_link(current_user, link)
        flash("Link revoked. The parent loses access on their next page load.", "success")
    except parent_service.LinkError as error:
        flash(str(error), "error")
    return redirect(url_for("admin.guardian_links"))
