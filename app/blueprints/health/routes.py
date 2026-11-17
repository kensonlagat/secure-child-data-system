"""Health and medication (#57). Social workers (own caseload) and administrators write;
the home manager reads and sees missed doses. Out of scope is 404 (audited, bounded)."""

from datetime import datetime

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.models.health import ADMINISTRATION_OUTCOMES, HEALTH_ENTRY_TYPES, MedicationSchedule
from app.services import health_service as health
from app.services.access_service import can_read_health, can_write_health, get_accessible_records
from app.services.audit_service import log_action

health_bp = Blueprint("health", __name__, template_folder="../../templates")


def _record_or_404(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None or not can_read_health(current_user, record):
        audit_access_denied("Denied health record access", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        abort(404)
    return record


def _post(record, action):
    if not can_write_health(current_user, record):
        audit_access_denied("Refused to change a health record", status_code=403, target_record_type="child_record",
                            target_record_id=record.id)
        abort(403)
    try:
        action()
        flash("Saved.", "success")
    except health.HealthError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("health.health_page", record_id=record.id))


@health_bp.route("/records/<int:record_id>")
@login_required
def health_page(record_id):
    record = _record_or_404(record_id)
    entries, schedules, log = health.overview(record.id)
    missed = health.missed_doses([record.id])
    log_action(user_id=current_user.id, action="health_record_viewed", target_record_type="child_record",
               target_record_id=record.id, details=f"Viewed health record ({len(missed)} missed dose(s) shown)")
    return render_template("health/record.html", record=record, entries=entries, schedules=schedules, log=log,
                           missed=missed, now=datetime.now(), todays_doses=health.todays_doses,
                           can_write=can_write_health(current_user, record), entry_types=HEALTH_ENTRY_TYPES,
                           outcomes=ADMINISTRATION_OUTCOMES)


@health_bp.route("/records/<int:record_id>/entries", methods=["POST"])
@login_required
def add_entry(record_id):
    record = _record_or_404(record_id)
    return _post(record, lambda: health.add_entry(current_user, record, request.form))


@health_bp.route("/records/<int:record_id>/schedules", methods=["POST"])
@login_required
def add_schedule(record_id):
    record = _record_or_404(record_id)
    return _post(record, lambda: health.add_schedule(current_user, record, request.form))


def _schedule_record(schedule_id):
    schedule = db.session.get(MedicationSchedule, schedule_id)
    return schedule, _record_or_404(schedule.child_record_id if schedule else 0)


@health_bp.route("/schedules/<int:schedule_id>/stop", methods=["POST"])
@login_required
def stop_schedule(schedule_id):
    schedule, record = _schedule_record(schedule_id)
    return _post(record, lambda: health.stop_schedule(current_user, schedule))


@health_bp.route("/schedules/<int:schedule_id>/doses", methods=["POST"])
@login_required
def record_dose(schedule_id):
    schedule, record = _schedule_record(schedule_id)
    return _post(record, lambda: health.record_dose(current_user, schedule, request.form))
