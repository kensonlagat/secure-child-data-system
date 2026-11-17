"""Authorised pickup list (#51). Records come only from access_service; anything out of
scope answers 404, with the real reason audited (bounded)."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.pickup import RELATIONSHIPS, AuthorisedCollector
from app.services import pickup_service
from app.services.access_service import (
    can_confirm_pickup,
    can_manage_pickup,
    can_view_collector_id_number,
    get_record_for_pickup,
)
from app.services.audit_service import log_action

pickup_bp = Blueprint("pickup", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_record_for_pickup(current_user, record_id)
    if record is None:
        audit_access_denied("Denied pickup list access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


@pickup_bp.route("/records/<int:record_id>")
@login_required
def collectors(record_id):
    record = _record_or_404(record_id)
    log_action(user_id=current_user.id, action="pickup_list_viewed", target_record_type="child_record",
               target_record_id=record.id, details="Viewed authorised collectors")
    return render_template("pickup/list.html", record=record, collectors=pickup_service.listed_collectors(record.id),
                           can_manage=can_manage_pickup(current_user, record),
                           can_confirm=can_confirm_pickup(current_user, record),
                           show_id_number=can_view_collector_id_number(current_user), relationships=RELATIONSHIPS)


@pickup_bp.route("/records/<int:record_id>/check")
@login_required
def gate_check(record_id):
    """Only what the gate needs: name, relationship and the last 3 characters of the ID."""
    record = _record_or_404(record_id)
    log_action(user_id=current_user.id, action="pickup_check_viewed", target_record_type="child_record",
               target_record_id=record.id, details="Viewed the pickup gate check")
    return render_template("pickup/check.html", record=record, collectors=pickup_service.active_collectors(record.id))


@pickup_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def add_collector(record_id):
    record = _record_or_404(record_id)
    if not can_manage_pickup(current_user, record):
        audit_access_denied("Refused to add a collector", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    confirmed = can_confirm_pickup(current_user, record)  # administrators: active at once
    try:
        pickup_service.add(current_user, record, *pickup_service.validate(request.form), confirmed=confirmed)
        flash("Collector added." if confirmed else
              "Collector proposed. They can't collect until an administrator confirms them.", "success")
    except pickup_service.PickupError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("pickup.collectors", record_id=record.id))


def _decide(collector_id, confirm):
    collector = db.session.get(AuthorisedCollector, collector_id)
    record = _record_or_404(collector.child_record_id if collector else 0)
    if not can_confirm_pickup(current_user, record):
        audit_access_denied("Refused to confirm or reject a collector", status_code=403,
                            target_record_type="child_record", target_record_id=record.id)
        abort(403)
    try:
        pickup_service.decide(current_user, collector, confirm=confirm)
        flash("Collector confirmed." if confirm else "Collector rejected.", "success")
    except pickup_service.PickupError as error:
        flash(str(error), "error")
    return redirect(url_for("pickup.collectors", record_id=record.id))


@pickup_bp.route("/collectors/<int:collector_id>/confirm", methods=["POST"])
@login_required
def confirm_collector(collector_id):
    return _decide(collector_id, confirm=True)


@pickup_bp.route("/collectors/<int:collector_id>/reject", methods=["POST"])
@login_required
def reject_collector(collector_id):
    return _decide(collector_id, confirm=False)


@pickup_bp.route("/collectors/<int:collector_id>/revoke", methods=["POST"])
@login_required
def revoke_collector(collector_id):
    collector = db.session.get(AuthorisedCollector, collector_id)
    record = _record_or_404(collector.child_record_id if collector else 0)
    if not can_manage_pickup(current_user, record):
        audit_access_denied("Refused to revoke a collector", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        pickup_service.revoke(current_user, collector)
        flash("Collector removed.", "success")
    except pickup_service.PickupError as error:
        flash(str(error), "error")
    return redirect(url_for("pickup.collectors", record_id=record.id))
