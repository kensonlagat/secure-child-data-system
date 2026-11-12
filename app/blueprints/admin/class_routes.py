"""Administrator class and enrolment management (#48).

Every change goes through app/services/enrolment_service.py, which enforces one current
enrolment per child and stages each change so it commits together with its audit row.
Child records are fetched only through access_service (hard rule 2), never directly.
"""

import re
from datetime import date

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.blueprints.admin.routes import admin_bp
from app.middleware.rbac import require_role
from app.models.child_record import ChildRecord
from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass
from app.models.user import Role, User
from app.services import enrolment_service as enrolment
from app.services.access_service import get_accessible_records

STREAM_PATTERN = re.compile(r"^[A-Za-z0-9]{0,10}$")


def _class_or_404(class_id):
    school_class = db.session.get(SchoolClass, class_id)
    if school_class is None:
        abort(404)
    return school_class


def _school_child_or_404(record_id):
    """A non-deleted school record the current administrator may access, else 404."""
    child = (
        get_accessible_records(current_user)
        .filter(ChildRecord.id == record_id, ChildRecord.institution_mode == "school")
        .first()
    )
    if child is None:
        abort(404)
    return child


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _validate_class_form(form, current=None):
    name = (form.get("name") or "").strip()
    stream = (form.get("stream") or "").strip().upper()
    year = _int(form.get("academic_year"))
    if not name or len(name) > 50:
        return None, "Enter a class name (up to 50 characters), for example Grade 6."
    if not STREAM_PATTERN.fullmatch(stream):
        return None, "The stream is up to 10 letters or digits, for example A."
    if year is None or not 2000 <= year <= 2100:
        return None, "Enter the academic year, for example 2026."
    clash = SchoolClass.query.filter_by(name=name, stream=stream, academic_year=year).first()
    if clash is not None and clash is not current:
        return None, "That class already exists for that academic year."
    return (name, stream, year), None


def _finish(error_message=None, success_message=None, class_id=None):
    if error_message:
        db.session.rollback()
        flash(error_message, "error")
    elif success_message:
        flash(success_message, "success")
    target = url_for("admin.class_detail", class_id=class_id) if class_id else url_for("admin.list_classes")
    return redirect(target)


@admin_bp.route("/classes")
@login_required
@require_role("administrator")
def list_classes():
    classes = SchoolClass.query.order_by(SchoolClass.is_active.desc(), SchoolClass.academic_year.desc(),
                                         SchoolClass.name, SchoolClass.stream).all()
    # Counted through access_service, so deleted records are never included.
    counts = dict(
        get_accessible_records(current_user)
        .join(Enrolment, Enrolment.child_record_id == ChildRecord.id)
        .filter(Enrolment.ended_on.is_(None))
        .with_entities(Enrolment.class_id, db.func.count(Enrolment.id))
        .group_by(Enrolment.class_id).all()
    )
    return render_template("admin/classes/list.html", classes=classes, counts=counts,
                           default_year=date.today().year)


@admin_bp.route("/classes", methods=["POST"])
@login_required
@require_role("administrator")
def create_class():
    values, error = _validate_class_form(request.form)
    if error:
        return _finish(error)
    school_class = enrolment.create_class(current_user, *values)
    return _finish(success_message=f"Class {school_class.label} created.", class_id=school_class.id)


@admin_bp.route("/classes/<int:class_id>")
@login_required
@require_role("administrator")
def class_detail(class_id):
    school_class = _class_or_404(class_id)
    enrolled = (
        get_accessible_records(current_user)
        .join(Enrolment, Enrolment.child_record_id == ChildRecord.id)
        .filter(Enrolment.class_id == class_id, Enrolment.ended_on.is_(None))
        .all()
    )
    unenrolled = (
        get_accessible_records(current_user)
        .filter(ChildRecord.institution_mode == "school")
        .filter(~ChildRecord.id.in_(db.session.query(Enrolment.child_record_id).filter(Enrolment.ended_on.is_(None))))
        .all()
    )
    teachers = (
        User.query.join(ClassTeacherAssignment, ClassTeacherAssignment.user_id == User.id)
        .filter(ClassTeacherAssignment.class_id == class_id, ClassTeacherAssignment.ended_at.is_(None)).all()
    )
    assignable = (
        User.query.join(Role).filter(Role.name == "teacher", User.is_active.is_(True))
        .filter(~User.id.in_([t.id for t in teachers])).order_by(User.full_name).all()
    )
    other_classes = (
        SchoolClass.query.filter(SchoolClass.is_active.is_(True), SchoolClass.id != class_id)
        .order_by(SchoolClass.academic_year.desc(), SchoolClass.name, SchoolClass.stream).all()
    )
    return render_template("admin/classes/detail.html", school_class=school_class, enrolled=enrolled,
                           unenrolled=unenrolled, teachers=teachers, assignable=assignable,
                           other_classes=other_classes)


@admin_bp.route("/classes/<int:class_id>/edit", methods=["POST"])
@login_required
@require_role("administrator")
def update_class(class_id):
    school_class = _class_or_404(class_id)
    values, error = _validate_class_form(request.form, current=school_class)
    if error:
        return _finish(error, class_id=class_id)
    changed = enrolment.update_class(current_user, school_class, *values)
    return _finish(success_message="Class updated." if changed else "No changes to save.", class_id=class_id)


@admin_bp.route("/classes/<int:class_id>/archive", methods=["POST"])
@login_required
@require_role("administrator")
def archive_class(class_id):
    school_class = _class_or_404(class_id)
    enrolment.set_class_active(current_user, school_class, False)
    return _finish(success_message=f"Class {school_class.label} archived. Its teachers no longer see its records.",
                   class_id=class_id)


@admin_bp.route("/classes/<int:class_id>/reactivate", methods=["POST"])
@login_required
@require_role("administrator")
def reactivate_class(class_id):
    school_class = _class_or_404(class_id)
    enrolment.set_class_active(current_user, school_class, True)
    return _finish(success_message=f"Class {school_class.label} reactivated.", class_id=class_id)


@admin_bp.route("/classes/<int:class_id>/teachers", methods=["POST"])
@login_required
@require_role("administrator")
def assign_class_teacher(class_id):
    school_class = _class_or_404(class_id)
    teacher = db.session.get(User, _int(request.form.get("user_id")) or 0)
    if teacher is None or not teacher.is_active:
        return _finish("Choose an active teacher.", class_id=class_id)
    try:
        enrolment.assign_teacher(current_user, school_class, teacher)
    except enrolment.EnrolmentError as error:
        return _finish(str(error), class_id=class_id)
    return _finish(success_message=f"{teacher.full_name} now teaches {school_class.label}.", class_id=class_id)


@admin_bp.route("/classes/<int:class_id>/teachers/<int:user_id>/remove", methods=["POST"])
@login_required
@require_role("administrator")
def unassign_class_teacher(class_id, user_id):
    school_class = _class_or_404(class_id)
    teacher = db.session.get(User, user_id)
    if teacher is None or not enrolment.unassign_teacher(current_user, school_class, teacher):
        return _finish("That teacher is not assigned to this class.", class_id=class_id)
    return _finish(success_message=f"{teacher.full_name} no longer teaches {school_class.label}.", class_id=class_id)


@admin_bp.route("/classes/<int:class_id>/enrol", methods=["POST"])
@login_required
@require_role("administrator")
def enrol_in_class(class_id):
    school_class = _class_or_404(class_id)
    child = _school_child_or_404(_int(request.form.get("child_record_id")) or 0)
    try:
        enrolment.enrol_child(current_user, child, school_class)
    except enrolment.EnrolmentError as error:
        return _finish(str(error), class_id=class_id)
    return _finish(success_message="Child enrolled.", class_id=class_id)


@admin_bp.route("/classes/<int:class_id>/promote", methods=["POST"])
@login_required
@require_role("administrator")
def promote_class(class_id):
    school_class = _class_or_404(class_id)
    target = db.session.get(SchoolClass, _int(request.form.get("target_class_id")) or 0)
    try:
        moved = enrolment.promote_class(current_user, school_class, target)
    except enrolment.EnrolmentError as error:
        return _finish(str(error), class_id=class_id)
    return _finish(success_message=f"Promoted {moved} children to {target.label}.", class_id=target.id)


@admin_bp.route("/records/<int:record_id>/class", methods=["POST"])
@login_required
@require_role("administrator")
def move_child_class(record_id):
    child = _school_child_or_404(record_id)
    target = db.session.get(SchoolClass, _int(request.form.get("class_id")) or 0)
    current = enrolment.current_enrolment(child.id)
    try:
        enrolment.move_child(current_user, child, target)
    except enrolment.EnrolmentError as error:
        return _finish(str(error), class_id=current.class_id if current else None)
    return _finish(success_message="Child moved.", class_id=target.id)


@admin_bp.route("/records/<int:record_id>/class/remove", methods=["POST"])
@login_required
@require_role("administrator")
def remove_child_class(record_id):
    child = _school_child_or_404(record_id)
    current = enrolment.current_enrolment(child.id)
    try:
        enrolment.remove_child_from_class(current_user, child)
    except enrolment.EnrolmentError as error:
        return _finish(str(error))
    return _finish(success_message="Child removed from the class.", class_id=current.class_id)
