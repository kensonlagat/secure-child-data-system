"""Missing and forbidden child records both answer 404; the audit log keeps the real reason."""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.user import Role, User

PASSWORD = "Password#2026"
MISSING_ID = 9999


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        teacher_role = Role(name="teacher", institution_mode="school")
        worker_role = Role(name="social_worker", institution_mode="childrens_home")
        db.session.add_all([teacher_role, worker_role])
        db.session.flush()
        db.session.add_all([
            User(email="teacher@example.com", full_name="T", phone_number="+254700000001", assigned_class="Grade 6A",
                 password_hash=generate_password_hash(PASSWORD), role_id=teacher_role.id),
            User(email="worker@example.com", full_name="W", phone_number="+254700000002",
                 password_hash=generate_password_hash(PASSWORD), role_id=worker_role.id),
        ])
        mine = ChildRecord(full_name="Mine", date_of_birth=date(2014, 1, 1), institution_mode="school",
                           class_assigned="Grade 6A", guardian_contact="+254711111111")
        forbidden = ChildRecord(full_name="Other class", date_of_birth=date(2014, 1, 1), institution_mode="school",
                                class_assigned="Grade 7C")
        home = ChildRecord(full_name="Home", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home")
        db.session.add_all([mine, forbidden, home])
        db.session.commit()
        application.config.update(MINE=mine.id, FORBIDDEN=forbidden.id, HOME=home.id)
    yield application
    with application.app_context():
        db.drop_all()


def sign_in(app, email, portal):
    client = app.test_client()
    assert client.post("/login", data={"email": email, "password": PASSWORD, "portal": portal}).status_code == 302
    return client


def rows(app, action):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=action, target_record_type="child_record").all()


@pytest.mark.parametrize("method, suffix, body", [("get", "/edit", None), ("patch", "", {"guardian_contact": "+254722222222"})])
def test_forbidden_and_missing_records_look_identical(app, method, suffix, body):
    teacher = sign_in(app, "teacher@example.com", "school")
    call = getattr(teacher, method)
    kwargs = {"json": body} if body else {}

    forbidden = call(f"/school/records/{app.config['FORBIDDEN']}{suffix}", **kwargs)
    missing = call(f"/school/records/{MISSING_ID}{suffix}", **kwargs)

    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.get_data() == missing.get_data()


def test_audit_log_keeps_the_real_reason(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    teacher.get(f"/school/records/{app.config['FORBIDDEN']}/edit")
    teacher.get(f"/school/records/{MISSING_ID}/edit")

    denied = rows(app, "access_denied")
    not_found = rows(app, "record_not_found")
    assert [r.target_record_id for r in denied] == [app.config["FORBIDDEN"]]
    assert [r.target_record_id for r in not_found] == [MISSING_ID]
    assert not_found[0].details == "Child record not found in school mode"


def test_probing_missing_ids_is_audited_but_bounded(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    for _ in range(20):
        teacher.get(f"/school/records/{MISSING_ID}/edit")

    assert len(rows(app, "record_not_found")) == 1


def test_cycling_through_missing_ids_cannot_flood_the_log(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    for missing_id in range(10_000, 10_040):
        assert teacher.get(f"/school/records/{missing_id}/edit").status_code == 404

    not_found = rows(app, "record_not_found")
    assert len(not_found) == 1
    assert not_found[0].target_record_id == 10_000  # the first ID tried is kept


def test_childrens_home_forbidden_record_is_404_too(app):
    worker = sign_in(app, "worker@example.com", "childrens_home")  # not on this child's caseload

    forbidden = worker.get(f"/home-mode/records/{app.config['HOME']}/edit")
    missing = worker.get(f"/home-mode/records/{MISSING_ID}/edit")

    assert forbidden.status_code == missing.status_code == 404
    assert len(rows(app, "access_denied")) == 1
    assert len(rows(app, "record_not_found")) == 1


def test_allowed_records_are_unaffected(app):
    teacher = sign_in(app, "teacher@example.com", "school")

    assert teacher.get(f"/school/records/{app.config['MINE']}/edit").status_code == 200
    assert rows(app, "access_denied") == [] and rows(app, "record_not_found") == []


def test_the_404_happens_even_if_the_audit_write_fails(app, monkeypatch):
    teacher = sign_in(app, "teacher@example.com", "school")

    def broken(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("app.services.audit_service.log_action", broken)

    assert teacher.get(f"/school/records/{app.config['FORBIDDEN']}/edit").status_code == 404
    assert teacher.get(f"/school/records/{MISSING_ID}/edit").status_code == 404
