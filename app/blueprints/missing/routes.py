"""Missing child alerts (#60). Any children's-home staff member raises; the home manager
and administrators resolve and see open alerts. Out of scope is 404 (audited, bounded)."""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied, require_role
from app.models.missing import MissingChildAlert
from app.services import missing_service as missing
from app.services.access_service import can_resolve_missing_alert, get_record_for_missing_alert
from app.services.audit_service import log_action

missing_bp = Blueprint("missing", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_record_for_missing_alert(current_user, record_id)
    if record is None:
        audit_access_denied("Denied missing child alert access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


def _alert_or_404(alert_id):
    alert = db.session.get(MissingChildAlert, alert_id)
    record = _record_or_404(alert.child_record_id if alert else 0)
    return alert, record


@missing_bp.route("/")
@login_required
@require_role("home_manager", "administrator")
def open_list():
    alerts = missing.open_alerts()
    log_action(user_id=current_user.id, action="missing_alerts_viewed", target_record_type="route",
               details=f"Viewed {len(alerts)} open missing alert(s)")
    return render_template("missing/list.html", alerts=alerts)


@missing_bp.route("/records/<int:record_id>")
@login_required
def alert_page(record_id):
    record = _record_or_404(record_id)
    alert = missing.open_alert(record.id)
    log_action(user_id=current_user.id, action="missing_child_viewed", target_record_type="child_record",
               target_record_id=record.id, details="Viewed missing alert" if alert else "Viewed missing alert form")
    return render_template("missing/record.html", record=record, alert=alert,
                           can_resolve=can_resolve_missing_alert(current_user))


@missing_bp.route("/records/<int:record_id>", methods=["POST"])
@login_required
def raise_alert(record_id):
    record = _record_or_404(record_id)
    try:
        missing.raise_alert(current_user, record, request.form)
        flash("Missing alert raised. The home manager has been alerted.", "success")
    except missing.MissingError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("missing.alert_page", record_id=record.id))


@missing_bp.route("/alerts/<int:alert_id>/actions", methods=["POST"])
@login_required
def update_actions(alert_id):
    alert, record = _alert_or_404(alert_id)
    try:
        missing.update_actions(current_user, alert, request.form)
        flash("Actions updated.", "success")
    except missing.MissingError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("missing.alert_page", record_id=record.id))


@missing_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve(alert_id):
    alert, record = _alert_or_404(alert_id)
    if not can_resolve_missing_alert(current_user):
        audit_access_denied("Refused to resolve a missing child alert", status_code=403,
                            target_record_type="child_record", target_record_id=record.id)
        abort(403)
    try:
        missing.resolve(current_user, alert, request.form)
        flash("Alert resolved.", "success")
    except missing.MissingError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("missing.alert_page", record_id=record.id))
