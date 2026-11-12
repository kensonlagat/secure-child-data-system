from types import SimpleNamespace

import pytest

from app.services import access_service

ROLE_NAMES = [
    "administrator",
    "teacher",
    "school_nurse",
    "social_worker",
    "legal_officer",
    "parent_guardian",
    "unknown",
]
PROTECTED_FIELDS = {
    "id",
    "institution_mode",
    "legal_status",
    "is_deleted",
    "deleted_at",
    "created_at",
    "updated_at",
    "class_assigned",  # #48: class changes go only through the audited enrolment actions
}
ADMIN_ALLOWLIST = [
    "full_name",
    "date_of_birth",
    "guardian_contact",
    "medical_notes",
    "caseload_worker_id",
]


def _user(role_name):
    return SimpleNamespace(
        id=1,
        role=SimpleNamespace(name=role_name),
    )


@pytest.mark.parametrize("role_name", ROLE_NAMES)
def test_writable_fields_exclude_protected_columns(monkeypatch, role_name):
    monkeypatch.setattr(access_service, "can_access_record", lambda user, record: True)

    fields = access_service.get_writable_fields(
        _user(role_name), SimpleNamespace(institution_mode="school")
    )

    assert not PROTECTED_FIELDS.intersection(fields)


def test_administrator_writable_fields_use_explicit_allowlist():
    fields = access_service.get_writable_fields(
        _user("administrator"),
        SimpleNamespace(institution_mode="school"),
    )

    assert fields == ADMIN_ALLOWLIST


def test_teacher_writable_fields_only_include_guardian_contact(monkeypatch):
    monkeypatch.setattr(access_service, "can_access_record", lambda user, record: True)

    fields = access_service.get_writable_fields(
        _user("teacher"),
        SimpleNamespace(institution_mode="school"),
    )

    assert fields == ["guardian_contact"]
