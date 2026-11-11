"""Record-level access_denied auditing is bounded and never blocks the refusal (#75).

Forbidden records answer 404 (see test_record_not_found_parity.py)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.user import Role, User

PASSWORD = "Password#2026"


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
        other_class = [ChildRecord(full_name=f"Child {i}", date_of_birth=date(2014, 1, 1), institution_mode="school",
                                   class_assigned="Grade 7C") for i in range(2)]
        home = ChildRecord(full_name="Home", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home")
        db.session.add_all(other_class + [home])
        db.session.commit()
        application.config["FORBIDDEN_IDS"] = [r.id for r in other_class]
        application.config["HOME_ID"] = home.id
    yield application
    with application.app_context():
        db.drop_all()


def sign_in(app, email, portal):
    client = app.test_client()
    assert client.post("/login", data={"email": email, "password": PASSWORD, "portal": portal}).status_code == 302
    return client


def denied_rows(app):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action="access_denied", target_record_type="child_record").all()


def test_hammering_a_forbidden_record_writes_one_row(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    record_id = app.config["FORBIDDEN_IDS"][0]

    for _ in range(25):
        assert teacher.get(f"/school/records/{record_id}/edit").status_code == 404

    rows = denied_rows(app)
    assert len(rows) == 1
    assert rows[0].target_record_id == record_id
    assert rows[0].details == "Denied child record access in school mode"


def test_each_record_is_audited_separately(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    for record_id in app.config["FORBIDDEN_IDS"]:
        teacher.get(f"/school/records/{record_id}/edit")

    assert sorted(r.target_record_id for r in denied_rows(app)) == sorted(app.config["FORBIDDEN_IDS"])


def test_a_new_window_audits_again(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    record_id = app.config["FORBIDDEN_IDS"][0]
    teacher.get(f"/school/records/{record_id}/edit")
    with app.app_context():  # test-only backdate in the in-memory DB
        for row in AuditLogEntry.query.filter_by(action="access_denied").all():
            row.timestamp = datetime.utcnow() - timedelta(seconds=61)
        db.session.commit()

    teacher.get(f"/school/records/{record_id}/edit")

    assert len(denied_rows(app)) == 2


def test_patch_attempts_are_bounded_too(app):
    teacher = sign_in(app, "teacher@example.com", "school")
    record_id = app.config["FORBIDDEN_IDS"][0]

    for _ in range(10):
        assert teacher.patch(f"/school/records/{record_id}", json={"guardian_contact": "+254711111111"}).status_code == 404

    assert len(denied_rows(app)) == 1


def test_childrens_home_record_refusals_are_bounded(app):
    worker = sign_in(app, "worker@example.com", "childrens_home")  # not on this child's caseload

    for _ in range(10):
        assert worker.get(f"/home-mode/records/{app.config['HOME_ID']}/edit").status_code == 404

    rows = denied_rows(app)
    assert len(rows) == 1
    assert rows[0].details == "Denied child record access in children's home mode"


def test_the_refusal_happens_even_if_the_audit_write_fails(app, monkeypatch):
    teacher = sign_in(app, "teacher@example.com", "school")

    def broken(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("app.services.audit_service.log_action", broken)
    monkeypatch.setattr("app.blueprints.school_mode.routes.log_action", broken)  # old direct import

    assert teacher.get(f"/school/records/{app.config['FORBIDDEN_IDS'][0]}/edit").status_code == 404
