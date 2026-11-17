"""Guardian consent records (#63)."""

from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.consent import ConsentRecord
from app.models.user import Role, User
from app.services import consent_service
from class_helpers import put_in_class

PASSWORD = "Password#2026"
GUARDIAN = "Grace Wambui (marker-c0n5)"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "social_worker": "childrens_home",
         "legal_officer": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for role_name, mode in ROLES.items():
            role = Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[role_name] = User(email=f"{role_name}@example.com", full_name=role_name, phone_number="+254700000001",
                                    password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[role_name])
        other_worker_role = Role.query.filter_by(name="social_worker").one()
        other_worker = User(email="worker2@example.com", full_name="Worker 2", phone_number="+254700000002",
                            password_hash=generate_password_hash(PASSWORD), role_id=other_worker_role.id, is_active=True)
        db.session.add(other_worker)
        db.session.flush()
        school = ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1), institution_mode="school")
        home = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           legal_status="in_state_care", caseload_worker_id=users["social_worker"].id)
        other_home = ChildRecord(full_name="Other Home Child", date_of_birth=date(2012, 1, 1),
                                 institution_mode="childrens_home", caseload_worker_id=other_worker.id)
        deleted = ChildRecord(full_name="Deleted", date_of_birth=date(2012, 1, 1), institution_mode="school",
                              is_deleted=True)
        db.session.add_all([school, home, other_home, deleted])
        db.session.flush()
        put_in_class("Grade 6A", children=[school], teachers=[users["teacher"]])
        db.session.commit()
        application.config.update(SCHOOL=school.id, HOME=home.id, OTHER_HOME=other_home.id, DELETED=deleted.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, role_name, email=None):
    client = app.test_client()
    mode = ROLES[role_name]
    assert client.post("/login", data={"email": email or f"{role_name}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[mode]}).status_code == 302
    return client


def form(consent_type="photo", status="given", effective_date=None, guardian_name=GUARDIAN):
    return {"consent_type": consent_type, "status": status, "guardian_name": guardian_name,
            "effective_date": (effective_date or date.today()).isoformat()}


def page_json(client, record_id):
    response = client.get(f"/consent/records/{record_id}", headers={"Accept": "application/json"})
    return response.status_code, response.get_json()


def rows(app, record_id=None):
    with app.app_context():
        query = ConsentRecord.query
        if record_id:
            query = query.filter_by(child_record_id=record_id)
        return query.count()


# --- Recording and withdrawing ---------------------------------------------------------------


def test_admin_records_consent_and_status_shows_it(app):
    admin = sign_in(app, "administrator")
    assert admin.post(f"/consent/records/{app.config['SCHOOL']}", json=form()).status_code == 201

    _, body = page_json(admin, app.config["SCHOOL"])
    assert body["status"]["photo"]["status"] == "given"
    assert body["status"]["medical_treatment"] is None


def test_withdrawal_is_a_new_row_and_nothing_is_deleted(app):
    admin = sign_in(app, "administrator")
    admin.post(f"/consent/records/{app.config['SCHOOL']}", json=form(effective_date=date.today() - timedelta(days=3)))
    admin.post(f"/consent/records/{app.config['SCHOOL']}", json=form(status="withdrawn"))

    _, body = page_json(admin, app.config["SCHOOL"])
    assert body["status"]["photo"]["status"] == "withdrawn"
    assert [entry["status"] for entry in body["history"]] == ["withdrawn", "given"]
    assert rows(app, app.config["SCHOOL"]) == 2


def test_has_consent_is_false_unless_the_latest_row_says_given(app):
    with app.app_context():
        record_id = app.config["SCHOOL"]
        admin = User.query.filter_by(email="administrator@example.com").one()
        child = db.session.get(ChildRecord, record_id)
        assert consent_service.has_consent(record_id, "photo") is False  # nothing recorded
        consent_service.record(admin, child, "photo", "given", date.today(), GUARDIAN)
        assert consent_service.has_consent(record_id, "photo") is True
        consent_service.record(admin, child, "photo", "withdrawn", date.today(), GUARDIAN)
        assert consent_service.has_consent(record_id, "photo") is False
        assert consent_service.has_consent(record_id, "data_sharing") is False


def test_social_worker_records_consent_on_their_own_caseload_only(app):
    worker = sign_in(app, "social_worker")
    assert worker.post(f"/consent/records/{app.config['HOME']}", json=form()).status_code == 201
    assert worker.post(f"/consent/records/{app.config['OTHER_HOME']}", json=form()).status_code == 404
    assert rows(app, app.config["OTHER_HOME"]) == 0


# --- Others see status only ------------------------------------------------------------------


def test_teacher_sees_status_only_and_cannot_record(app):
    sign_in(app, "administrator").post(f"/consent/records/{app.config['SCHOOL']}", json=form())
    teacher = sign_in(app, "teacher")

    status, body = page_json(teacher, app.config["SCHOOL"])
    html = teacher.get(f"/consent/records/{app.config['SCHOOL']}").get_data(as_text=True)
    refused = teacher.post(f"/consent/records/{app.config['SCHOOL']}", json=form(status="withdrawn"))

    assert status == 200 and body["status"]["photo"]["status"] == "given"
    assert "history" not in body and GUARDIAN not in str(body) and GUARDIAN not in html
    assert 'name="guardian_name"' not in html
    assert refused.status_code == 403 and rows(app) == 1


def test_legal_officer_sees_home_status_only(app):
    status, body = page_json(sign_in(app, "legal_officer"), app.config["HOME"])
    assert status == 200 and "history" not in body


# --- Out of scope: identical 404s, real reason audited ------------------------------------------


@pytest.mark.parametrize("role_name, key", [("school_nurse", "HOME"), ("teacher", "HOME"),
                                            ("administrator", "DELETED"), ("social_worker", "SCHOOL")])
def test_records_outside_scope_answer_404(app, role_name, key):
    client = sign_in(app, role_name)
    assert client.get(f"/consent/records/{app.config[key]}").status_code == 404
    assert client.post(f"/consent/records/{app.config[key]}", json=form()).status_code == 404


def test_missing_and_forbidden_records_look_the_same(app):
    nurse = sign_in(app, "school_nurse")
    forbidden = nurse.get(f"/consent/records/{app.config['HOME']}")
    missing = nurse.get("/consent/records/99999")
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.get_data() == missing.get_data()
    with app.app_context():
        actions = {row.action for row in AuditLogEntry.query.all()}
    assert {"access_denied", "record_not_found"} <= actions


# --- Validation, encryption, audit ------------------------------------------------------------------


@pytest.mark.parametrize("bad", [
    {"consent_type": "everything"}, {"status": "maybe"}, {"guardian_name": ""}, {"guardian_name": "x" * 121},
    {"effective_date": (date.today() + timedelta(days=1)).isoformat()}, {"effective_date": "yesterday"},
])
def test_invalid_input_is_refused(app, bad):
    response = sign_in(app, "administrator").post(f"/consent/records/{app.config['SCHOOL']}", json={**form(), **bad})
    assert response.status_code == 400
    assert rows(app) == 0


def test_guardian_name_is_ciphertext_at_rest(app):
    sign_in(app, "administrator").post(f"/consent/records/{app.config['SCHOOL']}", json=form())
    with app.app_context():
        stored = db.session.execute(text("SELECT guardian_name FROM consent_records")).scalar()
    assert GUARDIAN.encode() not in bytes(stored) and b"Wambui" not in bytes(stored)


def test_audit_rows_carry_type_and_status_but_never_the_guardian_name(app):
    admin = sign_in(app, "administrator")
    admin.post(f"/consent/records/{app.config['SCHOOL']}", json=form(consent_type="medical_treatment"))
    page_json(admin, app.config["SCHOOL"])

    with app.app_context():
        recorded = AuditLogEntry.query.filter_by(action="consent_recorded").one()
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    assert recorded.details == "Consent medical_treatment: given"
    assert "Wambui" not in details
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="consent_viewed").count() == 1


def test_record_list_links_to_consent(app):
    html = sign_in(app, "teacher").get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert f'/consent/records/{app.config["SCHOOL"]}' in html


def test_consent_records_are_registered_as_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert "consent_records" in APPEND_ONLY_TABLES and "audit_log_entries" in APPEND_ONLY_TABLES
