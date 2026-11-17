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
            "gender",
            CLASS_LABEL_FIELD,
            "guardian_contact",
            "allergies",
        ]

    if role_name == "school_nurse":
        return ["id", "full_name", "date_of_birth", "gender", "medical_notes", "allergies"]

    if role_name == "social_worker":
        return [
            "id",
            "full_name",
            "date_of_birth",
            "gender",
            "birth_certificate_number",
            "medical_notes",
            "allergies",
            "legal_status",
            "caseload_worker_id",
        ]

    if role_name == "legal_officer":
        return ["id", "full_name", "date_of_birth", "birth_certificate_number", "legal_status"]

    return []


def get_writable_fields(user, record):
    """Return the ChildRecord fields this user may update for the given record."""
    role_name = _get_role_name(user)
    if role_name == "administrator":
        # This is an allowlist: future columns are non-writable by default.
        # Excluded fields are institution_mode (role scopes), legal_status (two-person
        # workflow), is_deleted/deleted_at (OTP-gated deletion), id, and timestamps, and
        # class_assigned (#48: class changes go only through the audited enrolment actions).
        fields = [
            "full_name",
            "date_of_birth",
            "guardian_contact",
            "medical_notes",
            "caseload_worker_id",
            "gender",
            "birth_certificate_number",
            "allergies",
        ]
        if getattr(record, "institution_mode", None) == "school":
            fields.append("learner_upi")  # NEMIS UPI exists for school records only (#49a)
        return fields

    if role_name == "teacher":
        if not can_access_record(user, record):
            return []
        return ["guardian_contact"]

    if role_name == "school_nurse":
        if getattr(record, "institution_mode", None) != "school":
            return []
        return ["medical_notes", "allergies"]

    if role_name == "social_worker":
        if not can_access_record(user, record):
            return []
        return ["medical_notes", "allergies"]

    return []


# --- Consent (#63) ---------------------------------------------------------------------

CONSENT_RECORDER_ROLES = {"administrator", "social_worker"}


def can_view_consent_status(user, record):
    """Anyone who can open the record sees its consent status (type, given or withdrawn, date)."""
    return can_access_record(user, record)


def can_record_consent(user, record):
    """Administrators and social workers (their own caseload, via can_access_record) record
    consent. Everyone else, fail closed."""
    return _get_role_name(user) in CONSENT_RECORDER_ROLES and can_access_record(user, record)


def can_view_consent_details(user, record):
    """The guardian name and the full history are for the people who record consent."""
    return can_record_consent(user, record)


# --- Attendance (#50) -------------------------------------------------------------------


def can_mark_attendance(user, school_class):
    """Teachers mark only active classes they currently hold; administrators may mark or
    correct any class. Everyone else, fail closed."""
    role_name = _get_role_name(user)
    if school_class is None:
        return False
    if role_name == "administrator":
        return True
    if role_name == "teacher" and school_class.is_active:
        return ClassTeacherAssignment.query.filter_by(
            class_id=school_class.id, user_id=getattr(user, "id", None), ended_at=None
        ).first() is not None
    return False


def can_read_attendance(user, school_class):
    """Those who can mark, plus principals (read-only oversight of the school, per #50).
    Clinical officers and children's-home roles get nothing."""
    if can_mark_attendance(user, school_class):
        return True
    return school_class is not None and _get_role_name(user) == "principal"


# --- Authorised pickup list (#51) -----------------------------------------------------------


def _is_school_record(record):
    return (record is not None and getattr(record, "institution_mode", None) == "school"
            and not getattr(record, "is_deleted", True))


def can_manage_pickup(user, record):
    """Administrators (any school record) and teachers (records in their own classes) add and
    revoke collectors. Everyone else, fail closed."""
    if not _is_school_record(record):
        return False
    return _get_role_name(user) in {"administrator", "teacher"} and can_access_record(user, record)


def can_view_pickup(user, record):
    """Managers, plus principals (read-only oversight of school records)."""
    if not _is_school_record(record):
        return False
    return can_manage_pickup(user, record) or _get_role_name(user) == "principal"


def can_view_collector_id_number(user):
    """The full national ID number is for administrators; everyone else sees the last 3 characters."""
    return _get_role_name(user) == "administrator"


def get_record_for_pickup(user, record_id):
    """The school record for a pickup page, or None. Lives here (not in a route) because
    principals read pickup lists without having general record access (hard rule 2)."""
    record = ChildRecord.query.filter(
        ChildRecord.id == record_id,
        ChildRecord.is_deleted.is_(False),
        ChildRecord.institution_mode == "school",
    ).first()
    return record if can_view_pickup(user, record) else None


# --- Clinic visit log (#52) ----------------------------------------------------------------


def can_record_clinic(user, record):
    """Clinical officers record visits for school children in their scope. Fail closed."""
    return (_get_role_name(user) == "school_nurse" and record is not None
            and getattr(record, "institution_mode", None) == "school" and can_access_record(user, record))


def can_read_clinic(user, record):
    """Clinical officers and administrators read. Teachers and everyone else see nothing clinical."""
    if record is None or getattr(record, "institution_mode", None) != "school":
        return False
    if can_record_clinic(user, record):
        return True
    return _get_role_name(user) == "administrator" and can_access_record(user, record)
