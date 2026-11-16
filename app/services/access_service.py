"""Least-privilege record scoping for child record access.

This module is the single source of truth for which child records a user may
see and which fields are visible for that role. Every rule fails closed by
default: missing assignments, unknown roles, or incomplete user context return
an empty query or empty field list rather than broadening access.
"""

from sqlalchemy import false, select

from app.models.child_record import ChildRecord
from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass

# Derived, read-only field: the label of the child's current class (#48). It replaces the
# legacy free-text `class_assigned` column, which is neither visible nor writable any more.
CLASS_LABEL_FIELD = "class_label"
LEGACY_COLUMNS = {"class_assigned"}


def _empty_records_query():
    """Return a query that never yields any child records."""
    return ChildRecord.query.filter(false())


def _get_role_name(user):
    """Return the current user's role name when available."""
    if user is None or getattr(user, "role", None) is None:
        return None
    return user.role.name


def get_accessible_records(user):
    """Return the scoped ChildRecord query for the supplied user."""
    role_name = _get_role_name(user)
    base_query = ChildRecord.query.filter(ChildRecord.is_deleted.is_(False))

    if role_name == "administrator":
        return base_query

    if role_name == "teacher":
        user_id = getattr(user, "id", None)
        if user_id is None:
            return _empty_records_query()
        # Classes this teacher currently holds, archived classes excluded (#48).
        teacher_class_ids = (
            select(ClassTeacherAssignment.class_id)
            .join(SchoolClass, SchoolClass.id == ClassTeacherAssignment.class_id)
            .where(
                ClassTeacherAssignment.user_id == user_id,
                ClassTeacherAssignment.ended_at.is_(None),
                SchoolClass.is_active.is_(True),
            )
        )
        # Children whose *current* enrolment is in one of those classes. No assignment
        # means an empty subquery, so no records (fail closed).
        enrolled_child_ids = select(Enrolment.child_record_id).where(
            Enrolment.ended_on.is_(None),
            Enrolment.class_id.in_(teacher_class_ids),
        )
        return base_query.filter(
            ChildRecord.institution_mode == "school",
            ChildRecord.id.in_(enrolled_child_ids),
        )

    if role_name == "school_nurse":
        return base_query.filter(ChildRecord.institution_mode == "school")

    if role_name == "social_worker":
        return base_query.filter(
            ChildRecord.institution_mode == "childrens_home",
            ChildRecord.caseload_worker_id == user.id,
        )

    if role_name == "legal_officer":
        return base_query.filter(ChildRecord.institution_mode == "childrens_home")

    if role_name == "parent_guardian":
        return _empty_records_query()

    if role_name in {"principal", "home_manager"}:
        # Oversight roles (#47) see no records until their overview features grant
        # specific, read-only access (#53, #61). Explicit so the intent is reviewable.
        return _empty_records_query()

    return _empty_records_query()


def get_deleted_records(user):
    """Return deleted records for administrators only."""
    role_name = _get_role_name(user)
    if role_name != "administrator":
        return _empty_records_query()

    return ChildRecord.query.filter(ChildRecord.is_deleted.is_(True))


def can_access_record(user, record):
    """Return True only when the record's id appears in the scoped query."""
    if record is None or getattr(record, "id", None) is None:
        return False

    return (
        get_accessible_records(user)
        .with_entities(ChildRecord.id)
        .filter(ChildRecord.id == record.id)
        .first()
        is not None
    )


def get_visible_fields(user):
    """Return the ChildRecord fields visible to the supplied user's role."""
    role_name = _get_role_name(user)
    if role_name == "administrator":
        columns = [column.name for column in ChildRecord.__table__.columns if column.name not in LEGACY_COLUMNS]
        return columns + [CLASS_LABEL_FIELD]

    if role_name == "teacher":
        return [
            "id",
            "full_name",
            "date_of_birth",
            CLASS_LABEL_FIELD,
            "guardian_contact",
        ]

    if role_name == "school_nurse":
        return ["id", "full_name", "date_of_birth", "medical_notes"]

    if role_name == "social_worker":
        return [
            "id",
            "full_name",
            "date_of_birth",
            "medical_notes",
            "legal_status",
            "caseload_worker_id",
        ]

    if role_name == "legal_officer":
        return ["id", "full_name", "date_of_birth", "legal_status"]

    return []


def get_writable_fields(user, record):
    """Return the ChildRecord fields this user may update for the given record."""
    role_name = _get_role_name(user)
    if role_name == "administrator":
        # This is an allowlist: future columns are non-writable by default.
        # Excluded fields are institution_mode (role scopes), legal_status (two-person
        # workflow), is_deleted/deleted_at (OTP-gated deletion), id, and timestamps, and
        # class_assigned (#48: class changes go only through the audited enrolment actions).
        return [
            "full_name",
            "date_of_birth",
            "guardian_contact",
            "medical_notes",
            "caseload_worker_id",
        ]

    if role_name == "teacher":
        if not can_access_record(user, record):
            return []
        return ["guardian_contact"]

    if role_name == "school_nurse":
        if getattr(record, "institution_mode", None) != "school":
            return []
        return ["medical_notes"]

    if role_name == "social_worker":
        if not can_access_record(user, record):
            return []
        return ["medical_notes"]

    return []
