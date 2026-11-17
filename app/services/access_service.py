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
    base_query = ChildRecord.query.filter(ChildRecord.is_deleted.is_(False), ChildRecord.is_archived.is_(False))

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
        # Only children with an ACTIVE link to this parent (#67), school records only. Pending
        # and revoked links give nothing; revoking takes effect on the next request because
        # the status is read every time.
        from app.models.guardian_link import GuardianLink

        user_id = getattr(user, "id", None)
        if user_id is None:
            return _empty_records_query()
        linked = select(GuardianLink.child_record_id).where(
            GuardianLink.guardian_user_id == user_id, GuardianLink.status == "active")
        return base_query.filter(ChildRecord.institution_mode == "school", ChildRecord.id.in_(linked))

    if role_name == "home_manager":
        # Read-only oversight of the children's home (#54 onwards). Writes nothing
        # (get_writable_fields returns []), sees a reduced field set.
        return base_query.filter(ChildRecord.institution_mode == "childrens_home")

    if role_name == "principal":
        # School oversight is aggregate-only (#53); principals read registers and pickup
        # lists through their own access checks, never through general record access.
        return _empty_records_query()

    return _empty_records_query()


def get_archived_records(user):
    """Archived (left) records, for the administrator archive view only (#64). Never deleted."""
    if _get_role_name(user) != "administrator":
        return _empty_records_query()
    return ChildRecord.query.filter(ChildRecord.is_deleted.is_(False), ChildRecord.is_archived.is_(True))


def can_archive_records(user):
    """Archiving and restoring are administrator-only (#64)."""
    return _get_role_name(user) == "administrator"


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

    if role_name == "home_manager":
        # Oversight, not care: no medical notes, allergies or identity numbers.
        return ["id", "full_name", "date_of_birth", "gender", "legal_status", "caseload_worker_id"]

    if role_name == "parent_guardian":
        # Minimal set (#67). Attendance summary and consent status come from their own services.
        # Never: medical notes, allergies, safeguarding, legal status, documents, caseload, contacts.
        return ["id", "full_name", CLASS_LABEL_FIELD]

    return []


def get_writable_fields(user, record):
    """Return the ChildRecord fields this user may update for the given record."""
    role_name = _get_role_name(user)
    if getattr(record, "is_archived", False):
        return []  # archived records are read-only for every role (#64)
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
            and not getattr(record, "is_deleted", True) and not getattr(record, "is_archived", False))


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


def can_confirm_pickup(user, record):
    """Only administrators confirm or reject collectors proposed by teachers (#112), so a
    teacher can never confirm their own addition."""
    return _get_role_name(user) == "administrator" and can_manage_pickup(user, record)


def can_view_collector_id_number(user):
    """The full national ID number is for administrators; everyone else sees the last 3 characters."""
    return _get_role_name(user) == "administrator"


def get_record_for_pickup(user, record_id):
    """The school record for a pickup page, or None. Lives here (not in a route) because
    principals read pickup lists without having general record access (hard rule 2)."""
    record = ChildRecord.query.filter(
        ChildRecord.id == record_id,
        ChildRecord.is_deleted.is_(False), ChildRecord.is_archived.is_(False),
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


# --- Admission and intake (#54) -------------------------------------------------------------


def _is_home_record(record):
    return (record is not None and getattr(record, "institution_mode", None) == "childrens_home"
            and not getattr(record, "is_deleted", True) and not getattr(record, "is_archived", False))


def can_write_intake(user, record):
    """Administrators (any home record) and social workers (own caseload). Fail closed."""
    return (_is_home_record(record) and _get_role_name(user) in {"administrator", "social_worker"}
            and can_access_record(user, record))


def can_read_intake(user, record):
    """Writers, plus legal officers and the home manager (read only)."""
    if can_write_intake(user, record):
        return True
    return (_is_home_record(record) and _get_role_name(user) in {"legal_officer", "home_manager"}
            and can_access_record(user, record))


# --- Care plan and case notes (#55) -------------------------------------------------------------


def can_write_care_plan(user, record):
    """Only the assigned social worker (the record's caseload worker) writes goals and notes."""
    return (_is_home_record(record) and _get_role_name(user) == "social_worker"
            and getattr(record, "caseload_worker_id", None) == getattr(user, "id", None)
            and can_access_record(user, record))


def can_read_care_plan(user, record):
    """The assigned social worker and the home manager read goals and full notes."""
    if can_write_care_plan(user, record):
        return True
    return _is_home_record(record) and _get_role_name(user) == "home_manager" and can_access_record(user, record)


def can_read_legal_summaries(user, record):
    """Legal officers see only the legal summaries of case notes, never goals or note bodies."""
    return _is_home_record(record) and _get_role_name(user) == "legal_officer" and can_access_record(user, record)


# --- Court dates (#56) -----------------------------------------------------------------------


def can_manage_court(user, record):
    """Legal officers manage hearings for children's-home records. Fail closed."""
    return _is_home_record(record) and _get_role_name(user) == "legal_officer" and can_access_record(user, record)


def can_read_court(user, record):
    """Managers, plus the home manager and the assigned social worker (read only)."""
    if can_manage_court(user, record):
        return True
    if not _is_home_record(record) or not can_access_record(user, record):
        return False
    role_name = _get_role_name(user)
    if role_name == "home_manager":
        return True
    return role_name == "social_worker" and getattr(record, "caseload_worker_id", None) == getattr(user, "id", None)


# --- Health and medication (#57) -------------------------------------------------------------


def can_write_health(user, record):
    """Social workers (own caseload, via can_access_record) and administrators. Fail closed."""
    return (_is_home_record(record) and _get_role_name(user) in {"social_worker", "administrator"}
            and can_access_record(user, record))


def can_read_health(user, record):
    """Writers, plus the home manager (read only, including missed doses)."""
    if can_write_health(user, record):
        return True
    return _is_home_record(record) and _get_role_name(user) == "home_manager" and can_access_record(user, record)


# --- Family contact and visits (#58) -----------------------------------------------------------


def can_write_family(user, record):
    """Only the assigned social worker records visits and tracing. Fail closed."""
    return (_is_home_record(record) and _get_role_name(user) == "social_worker"
            and getattr(record, "caseload_worker_id", None) == getattr(user, "id", None)
            and can_access_record(user, record))


def can_read_family(user, record):
    """The assigned social worker and the home manager (read only)."""
    if can_write_family(user, record):
        return True
    return _is_home_record(record) and _get_role_name(user) == "home_manager" and can_access_record(user, record)


# --- Placement, reintegration and aftercare (#59) ----------------------------------------------


def can_write_placement(user, record):
    """Only the assigned social worker records placements and follow-ups. Fail closed.
    Nothing in this feature can change legal_status (hard rule 3)."""
    return (_is_home_record(record) and _get_role_name(user) == "social_worker"
            and getattr(record, "caseload_worker_id", None) == getattr(user, "id", None)
            and can_access_record(user, record))


def can_read_placement(user, record):
    """The assigned social worker, plus legal officers and the home manager (read only)."""
    if can_write_placement(user, record):
        return True
    return (_is_home_record(record) and _get_role_name(user) in {"legal_officer", "home_manager"}
            and can_access_record(user, record))


# --- Missing child alerts (#60) -------------------------------------------------------------

HOME_STAFF_ROLES = {"social_worker", "legal_officer", "home_manager", "administrator"}


def get_record_for_missing_alert(user, record_id):
    """Any children's-home staff member may raise an alert for any home child (a child is not
    missing only from their own caseload). Lives here, not in a route (hard rule 2)."""
    if _get_role_name(user) not in HOME_STAFF_ROLES:
        return None
    return ChildRecord.query.filter(
        ChildRecord.id == record_id,
        ChildRecord.is_deleted.is_(False), ChildRecord.is_archived.is_(False),
        ChildRecord.institution_mode == "childrens_home",
    ).first()


def can_view_missing_alert_details(user, alert):
    """Circumstances, actions taken and resolution notes (#122): only the person who raised the
    alert, the home manager and administrators. Other home staff see the child's name and when
    the child was last seen, which is what they need to help search. Applies after resolution too."""
    if alert is None:
        return False
    if _get_role_name(user) in {"home_manager", "administrator"}:
        return True
    return getattr(user, "id", None) is not None and alert.raised_by == user.id


def can_resolve_missing_alert(user):
    """The home manager and administrators resolve alerts."""
    return _get_role_name(user) in {"home_manager", "administrator"}


# --- Encrypted documents (#66) -----------------------------------------------------------------
# The confirmed type table (design note on #66). Record scope still comes from
# can_access_record, so a social worker only reaches their own caseload, a clinical officer only
# school records and a legal officer only children's-home records.
DOCUMENT_RULES = {
    "birth_certificate": {"modes": {"school", "childrens_home"}, "upload": {"administrator"},
                          "view": {"administrator", "social_worker", "legal_officer"}},
    "court_order": {"modes": {"childrens_home"}, "upload": {"administrator", "legal_officer"},
                    "view": {"administrator", "legal_officer", "social_worker"}},
    "medical_report": {"modes": {"school", "childrens_home"},
                       "upload": {"administrator", "school_nurse", "social_worker"},
                       "view": {"administrator", "school_nurse", "social_worker"}},
}


def _document_allowed(user, record, document_type, action):
    rule = DOCUMENT_RULES.get(document_type)
    if rule is None or record is None or getattr(record, "institution_mode", None) not in rule["modes"]:
        return False
    return _get_role_name(user) in rule[action] and can_access_record(user, record)


def can_upload_document(user, record, document_type):
    return _document_allowed(user, record, document_type, "upload")


def can_view_document(user, record, document_type):
    return _document_allowed(user, record, document_type, "view")


def can_delete_document(user):
    """Soft deletion is administrator-only and OTP-gated (hard rule 4 applied to documents)."""
    return _get_role_name(user) == "administrator"


# --- Child photos (#87) ---------------------------------------------------------------------

PHOTO_VIEW_ROLES = {"administrator", "teacher", "school_nurse", "social_worker"}


def can_view_photo(user, record):
    """Allowed roles, within their record scope, and only when photo consent is given (#63).
    Missing consent means no photo."""
    from app.services.consent_service import has_consent

    return (record is not None and _get_role_name(user) in PHOTO_VIEW_ROLES and can_access_record(user, record)
            and has_consent(record.id, "photo"))


def can_upload_photo(user, record):
    """Administrators upload photos."""
    return _get_role_name(user) == "administrator" and can_access_record(user, record)


# --- Report cards (#70) ---------------------------------------------------------------------

REPORT_READER_ROLES = {"administrator", "principal"}


def _teaches_class(user, class_id):
    """True only for a current assignment to an active class."""
    return (ClassTeacherAssignment.query.join(SchoolClass, SchoolClass.id == ClassTeacherAssignment.class_id)
            .filter(ClassTeacherAssignment.class_id == class_id,
                    ClassTeacherAssignment.user_id == getattr(user, "id", None),
                    ClassTeacherAssignment.ended_at.is_(None), SchoolClass.is_active.is_(True))
            .first() is not None)


def can_enter_marks(user, school_class, record):
    """Teachers only, for their own active class, and only for a child currently enrolled in it.
    Archived and deleted children are excluded. Administrators and principals read, never write."""
    if _get_role_name(user) != "teacher" or school_class is None or not _is_school_record(record):
        return False
    if not school_class.is_active or not _teaches_class(user, school_class.id):
        return False
    return Enrolment.query.filter_by(child_record_id=record.id, class_id=school_class.id,
                                     ended_on=None).first() is not None


def can_read_class_reports(user, school_class):
    """The class teacher, principals and administrators."""
    if school_class is None:
        return False
    role_name = _get_role_name(user)
    if role_name in REPORT_READER_ROLES:
        return True
    return role_name == "teacher" and _teaches_class(user, school_class.id)


def can_read_report_card(user, record):
    """Principals and administrators read any school child's cards; teachers read the cards of
    children currently in their scope (so a new class teacher sees earlier terms, a former one
    does not). Archived and deleted children are excluded for everyone."""
    if not _is_school_record(record):
        return False
    role_name = _get_role_name(user)
    if role_name in REPORT_READER_ROLES:
        return True
    return role_name == "teacher" and can_access_record(user, record)


def get_record_for_report_card(user, record_id):
    """The school record for a report-card page, or None. Lives here because principals read
    report cards without general record access (hard rule 2)."""
    record = ChildRecord.query.filter(
        ChildRecord.id == record_id,
        ChildRecord.is_deleted.is_(False), ChildRecord.is_archived.is_(False),
        ChildRecord.institution_mode == "school",
    ).first()
    return record if can_read_report_card(user, record) else None


# --- Parent portal (#67) --------------------------------------------------------------------


def can_manage_guardian_links(user):
    """Creating, verifying and revoking guardian links is administrator-only."""
    return _get_role_name(user) == "administrator"
