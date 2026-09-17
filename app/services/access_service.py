"""Least-privilege record scoping for child record access.

This module is the single source of truth for which child records a user may
see and which fields are visible for that role. Every rule fails closed by
default: missing assignments, unknown roles, or incomplete user context return
an empty query or empty field list rather than broadening access.
"""

from sqlalchemy import false

from app.models.child_record import ChildRecord


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
    if role_name == "administrator":
        return ChildRecord.query

    if role_name == "teacher":
        assigned_class = getattr(user, "assigned_class", None)
        if not assigned_class:
            return _empty_records_query()
        return ChildRecord.query.filter(
            ChildRecord.institution_mode == "school",
            ChildRecord.class_assigned == assigned_class,
        )

    if role_name == "school_nurse":
        return ChildRecord.query.filter(ChildRecord.institution_mode == "school")

    if role_name == "social_worker":
        return ChildRecord.query.filter(
            ChildRecord.institution_mode == "childrens_home",
            ChildRecord.caseload_worker_id == user.id,
        )

    if role_name == "legal_officer":
        return ChildRecord.query.filter(ChildRecord.institution_mode == "childrens_home")

    if role_name == "parent_guardian":
        return _empty_records_query()

    return _empty_records_query()


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
        return [column.name for column in ChildRecord.__table__.columns]

    if role_name == "teacher":
        return ["id", "full_name", "date_of_birth", "class_assigned", "guardian_contact"]

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
        excluded_fields = {"id", "created_at", "updated_at", "legal_status"}
        # Legal status changes must go through the dedicated two-person approval workflow,
        # not a direct field update, regardless of role.
        return [
            column.name
            for column in ChildRecord.__table__.columns
            if column.name not in excluded_fields
        ]

    if role_name == "teacher":
        if not can_access_record(user, record):
            return []
        return ["guardian_contact", "class_assigned"]

    if role_name == "school_nurse":
        if getattr(record, "institution_mode", None) != "school":
            return []
        return ["medical_notes"]

    if role_name == "social_worker":
        if not can_access_record(user, record):
            return []
        return ["medical_notes"]

    return []