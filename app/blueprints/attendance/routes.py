"""Attendance registers (#50). Teachers mark their own active classes; administrators read
and correct; principals read. A class the user can't read answers 404, audited (bounded)."""

from datetime import date

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.attendance import ATTENDANCE_STATUSES
from app.models.school_class import ClassTeacherAssignment, SchoolClass
from app.services import attendance_service
from app.services.access_service import can_mark_attendance, can_read_attendance
from app.services.audit_service import log_action

attendance_bp = Blueprint("attendance", __name__, template_folder="../../templates")


def _class_or_404(class_id):
    school_class = db.session.get(SchoolClass, class_id)
    if school_class is None or not can_read_attendance(current_user, school_class):
        audit_access_denied("Denied attendance register access", status_code=404,
                            target_record_type="school_class", target_record_id=class_id)
        abort(404)
    return school_class


def _register_date():
    raw = request.args.get("date")
    if not raw:
        return date.today()
    try:
        return date.fromisoformat(raw)
    except ValueError:
        abort(400)


@attendance_bp.route("/")
@login_required
def class_list():
    role = getattr(current_user.role, "name", None)
    if role == "teacher":
        classes = (SchoolClass.query.join(ClassTeacherAssignment, ClassTeacherAssignment.class_id == SchoolClass.id)
                   .filter(ClassTeacherAssignment.user_id == current_user.id, ClassTeacherAssignment.ended_at.is_(None),
                           SchoolClass.is_active.is_(True)).all())
    elif role in ("administrator", "principal"):
        classes = SchoolClass.query.filter_by(is_active=True).order_by(SchoolClass.name, SchoolClass.stream).all()
    else:
        audit_access_denied("Denied attendance access", status_code=403)
        abort(403)
    return render_template("attendance/classes.html", classes=classes, today=date.today())


@attendance_bp.route("/classes/<int:class_id>", methods=["GET"])
@login_required
def register(class_id):
    school_class = _class_or_404(class_id)
    register_date = _register_date()
    existing = attendance_service.get_register(school_class, register_date)
    marks = {mark.child_record_id: mark.status for mark in existing.marks} if existing else {}
    log_action(user_id=current_user.id, action="attendance_register_viewed", target_record_type="school_class",
               target_record_id=school_class.id, details=f"Register {register_date.isoformat()}")
    return render_template("attendance/register.html", school_class=school_class, register_date=register_date,
                           children=attendance_service.class_children(school_class), marks=marks,
                           statuses=ATTENDANCE_STATUSES, can_mark=can_mark_attendance(current_user, school_class),
                           is_past=register_date < date.today(), is_future=register_date > date.today())


@attendance_bp.route("/classes/<int:class_id>", methods=["POST"])
@login_required
def save(class_id):
    school_class = _class_or_404(class_id)
    if not can_mark_attendance(current_user, school_class):
        audit_access_denied("Refused to mark attendance", status_code=403, target_record_type="school_class",
                            target_record_id=school_class.id)
        abort(403)
    register_date = _register_date()
    statuses = {}
    for key, value in request.form.items():
        if key.startswith("status_"):
            child_id = key.removeprefix("status_")
            if not child_id.isdigit():
                abort(400)
            statuses[int(child_id)] = value
    try:
        attendance_service.save_register(current_user, school_class, register_date, statuses,
                                         reason=request.form.get("reason"))
    except attendance_service.AttendanceError as error:
        db.session.rollback()
        flash(str(error), "error")
        return redirect(url_for("attendance.register", class_id=class_id, date=register_date.isoformat()))
    flash("Register saved.", "success")
    return redirect(url_for("attendance.register", class_id=class_id, date=register_date.isoformat()))
