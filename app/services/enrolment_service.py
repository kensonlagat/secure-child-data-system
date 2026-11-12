"""The only code path that changes classes, teacher assignments and enrolments (#48).

Rules:
- At most one current enrolment per child, checked here before every change (the
  partial unique index on `enrolments` is only a backstop).
- Only active school-mode records that are not deleted can be enrolled, and only into
  active classes.
- Functions stage changes without committing. Callers finish with log_action(), which
  commits the change together with its audit row, so a change is never saved unaudited.
  Audit details carry ids and counts only, never child names.
"""

from datetime import date, datetime

from app import db
from app.models.child_record import ChildRecord
from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass
from app.services.audit_service import log_action


class EnrolmentError(ValueError):
    """A request that breaks an enrolment rule. The message is safe to show."""


def current_enrolment(child_record_id):
    return Enrolment.query.filter_by(child_record_id=child_record_id, ended_on=None).first()


def _check_enrollable(child, school_class):
    if child is None or child.is_deleted or child.institution_mode != "school":
        raise EnrolmentError("Only active school records can be enrolled in a class.")
    if school_class is None or not school_class.is_active:
        raise EnrolmentError("Choose an active class.")


def _open(child, school_class, actor_id, reason):
    if current_enrolment(child.id) is not None:  # the one-current-enrolment rule
        raise EnrolmentError("This child already has a current class. Move them instead.")
    enrolment = Enrolment(child_record_id=child.id, class_id=school_class.id, started_on=date.today(),
                          reason=reason, created_by=actor_id)
    db.session.add(enrolment)
    db.session.flush()
    return enrolment


def _close(enrolment, end_reason):
    enrolment.ended_on = date.today()
    enrolment.end_reason = end_reason
    db.session.flush()


# --- Classes -------------------------------------------------------------------------


def create_class(actor, name, stream, academic_year):
    school_class = SchoolClass(name=name, stream=stream, academic_year=academic_year, is_active=True)
    db.session.add(school_class)
    db.session.flush()
    log_action(user_id=actor.id, action="class_created", target_record_type="school_class",
               target_record_id=school_class.id, details=f"Created class for academic year {academic_year}")
    return school_class


def update_class(actor, school_class, name, stream, academic_year):
    changed = [field for field, value in (("name", name), ("stream", stream), ("academic_year", academic_year))
               if getattr(school_class, field) != value]
    if not changed:
        return []
    school_class.name, school_class.stream, school_class.academic_year = name, stream, academic_year
    log_action(user_id=actor.id, action="class_updated", target_record_type="school_class",
               target_record_id=school_class.id, details=f"Updated fields: {', '.join(changed)}")
    return changed


def set_class_active(actor, school_class, active):
    if school_class.is_active == active:
        return False
    school_class.is_active = active
    log_action(user_id=actor.id, action="class_reactivated" if active else "class_archived",
               target_record_type="school_class", target_record_id=school_class.id,
               details="Class reactivated" if active else "Class archived; it grants no teacher access")
    return True


# --- Teacher assignments ---------------------------------------------------------------


def current_assignment(class_id, user_id):
    return ClassTeacherAssignment.query.filter_by(class_id=class_id, user_id=user_id, ended_at=None).first()


def assign_teacher(actor, school_class, teacher, *, audit=True):
    if getattr(teacher.role, "name", None) != "teacher":
        raise EnrolmentError("Only teachers can be assigned to a class.")
    if not school_class.is_active:
        raise EnrolmentError("Choose an active class.")
    if current_assignment(school_class.id, teacher.id) is not None:
        return False
    db.session.add(ClassTeacherAssignment(class_id=school_class.id, user_id=teacher.id))
    db.session.flush()
    if audit:
        log_action(user_id=actor.id, action="class_teacher_assigned", target_record_type="school_class",
                   target_record_id=school_class.id, details=f"Assigned teacher user_id={teacher.id}")
    return True


def unassign_teacher(actor, school_class, teacher, *, audit=True):
    assignment = current_assignment(school_class.id, teacher.id)
    if assignment is None:
        return False
    assignment.ended_at = datetime.utcnow()
    db.session.flush()
    if audit:
        log_action(user_id=actor.id, action="class_teacher_unassigned", target_record_type="school_class",
                   target_record_id=school_class.id, details=f"Unassigned teacher user_id={teacher.id}")
    return True


def current_class_ids_for_teacher(user_id):
    return [row.class_id for row in ClassTeacherAssignment.query.filter_by(user_id=user_id, ended_at=None)]


# --- Enrolment ---------------------------------------------------------------------------


def enrol_child(actor, child, school_class, *, reason="enrolled", audit=True):
    _check_enrollable(child, school_class)
    enrolment = _open(child, school_class, actor.id, reason)
    if audit:
        log_action(user_id=actor.id, action="child_enrolled", target_record_type="child_record",
                   target_record_id=child.id, details=f"Enrolled in class_id={school_class.id}")
    return enrolment


def move_child(actor, child, to_class):
    _check_enrollable(child, to_class)
    existing = current_enrolment(child.id)
    if existing is None:
        raise EnrolmentError("This child has no current class. Enrol them instead.")
    if existing.class_id == to_class.id:
        raise EnrolmentError("The child is already in that class.")
    from_class_id = existing.class_id
    _close(existing, "moved")
    _open(child, to_class, actor.id, "moved")
    log_action(user_id=actor.id, action="child_moved", target_record_type="child_record", target_record_id=child.id,
               details=f"Moved from class_id={from_class_id} to class_id={to_class.id}")


def remove_child_from_class(actor, child):
    existing = current_enrolment(child.id)
    if existing is None:
        raise EnrolmentError("This child has no current class.")
    _close(existing, "left")
    log_action(user_id=actor.id, action="child_left_class", target_record_type="child_record",
               target_record_id=child.id, details=f"Left class_id={existing.class_id}")


def promote_class(actor, from_class, to_class):
    """Move every current enrolment of one class to another in one transaction, with one
    audit row. Any failure rolls the whole promotion back."""
    if to_class is None or not to_class.is_active:
        raise EnrolmentError("Choose an active class to promote into.")
    if to_class.id == from_class.id:
        raise EnrolmentError("Choose a different class to promote into.")
    enrolments = Enrolment.query.filter_by(class_id=from_class.id, ended_on=None).all()
    if not enrolments:
        raise EnrolmentError("This class has no enrolled children to promote.")
    promoted = 0
    try:
        for enrolment in enrolments:
            child = db.session.get(ChildRecord, enrolment.child_record_id)
            _close(enrolment, "promoted")
            if child.is_deleted:
                continue  # deleted records are closed out, not carried forward
            _check_enrollable(child, to_class)
            _open(child, to_class, actor.id, "promoted")
            promoted += 1
        log_action(user_id=actor.id, action="class_promoted", target_record_type="school_class",
                   target_record_id=from_class.id,
                   details=f"Promoted {promoted} children from class_id={from_class.id} to class_id={to_class.id}")
    except Exception:
        db.session.rollback()
        raise
    return promoted
