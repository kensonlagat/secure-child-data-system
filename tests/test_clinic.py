"""Clinic visit log (#52)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.clinic import ClinicVisit
from app.models.user import Role, User
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
         "social_worker": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}
VISIT = {"complaint": "Headache (marker-cl1n)", "treatment": "Rest and water", "medicines_given": "Paracetamol 250mg",
         "follow_up": "Check tomorrow", "immunisation": ""}


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
        db.session.flush()
        school = ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1), institution_mode="school")
        home = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           caseload_worker_id=users["social_worker"].id)
        deleted = ChildRecord(full_name="Deleted", date_of_birth=date(2014, 1, 1), institution_mode="school",
                              is_deleted=True)
        db.session.add_all([school, home, deleted])
        db.session.flush()
        put_in_class("Grade 6A", children=[school], teachers=[users["teacher"]])
        db.session.commit()
        application.config.update(SCHOOL=school.id, HOME=home.id, DELETED=deleted.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, role_name):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{role_name}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[role_name]]}).status_code == 302
    return client


def add(app, client, key="SCHOOL", **overrides):
    return client.post(f"/clinic/records/{app.config[key]}", data={**VISIT, **overrides})


def count(app):
    with app.app_context():
        return ClinicVisit.query.count()


def test_clinical_officer_records_and_reads_visits(app):
    nurse = sign_in(app, "school_nurse")
    assert add(app, nurse).status_code == 302
    html = nurse.get(f"/clinic/records/{app.config['SCHOOL']}").get_data(as_text=True)
    assert "marker-cl1n" in html and "Paracetamol" in html and count(app) == 1


def test_administrator_reads_but_cannot_record(app):
    add(app, sign_in(app, "school_nurse"))
    admin = sign_in(app, "administrator")
    html = admin.get(f"/clinic/records/{app.config['SCHOOL']}").get_data(as_text=True)
    assert "marker-cl1n" in html and 'name="complaint"' not in html
    assert add(app, admin, complaint="Other").status_code == 403
    assert count(app) == 1


@pytest.mark.parametrize("role_name", ["teacher", "principal", "social_worker"])
def test_teachers_and_others_cannot_read_clinical_entries(app, role_name):
    add(app, sign_in(app, "school_nurse"))
    client = sign_in(app, role_name)
    response = client.get(f"/clinic/records/{app.config['SCHOOL']}")
    assert response.status_code == 404
    assert "marker-cl1n" not in response.get_data(as_text=True)
    assert add(app, client).status_code == 404
    assert count(app) == 1


@pytest.mark.parametrize("role_name, key", [("school_nurse", "HOME"), ("school_nurse", "DELETED"),
                                            ("administrator", "HOME")])
def test_only_active_school_records(app, role_name, key):
    client = sign_in(app, role_name)
    assert client.get(f"/clinic/records/{app.config[key]}").status_code == 404
    assert add(app, client, key).status_code == 404


def test_teacher_record_list_has_no_clinic_link(app):
    html = sign_in(app, "teacher").get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert "/clinic/records/" not in html
    nurse_html = sign_in(app, "school_nurse").get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert f"/clinic/records/{app.config['SCHOOL']}" in nurse_html


@pytest.mark.parametrize("bad", [{"complaint": ""}, {"treatment": ""}, {"complaint": "x" * 501},
                                 {"visited_at": (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")},
                                 {"visited_at": "noon"}])
def test_invalid_visits_are_refused(app, bad):
    add(app, sign_in(app, "school_nurse"), **bad)
    assert count(app) == 0


def test_clinical_text_is_ciphertext_at_rest(app):
    add(app, sign_in(app, "school_nurse"))
    with app.app_context():
        row = db.session.execute(text("SELECT complaint, treatment, medicines_given, follow_up FROM clinic_visits")).one()
    stored = b"".join(bytes(value) for value in row)
    for plain in (b"marker-cl1n", b"Rest and water", b"Paracetamol", b"Check tomorrow"):
        assert plain not in stored


def test_audit_rows_carry_no_clinical_text(app):
    nurse = sign_in(app, "school_nurse")
    add(app, nurse)
    nurse.get(f"/clinic/records/{app.config['SCHOOL']}")
    with app.app_context():
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
        assert AuditLogEntry.query.filter_by(action="clinic_visit_recorded").count() == 1
        assert AuditLogEntry.query.filter_by(action="clinic_visits_viewed").count() == 1
    for secret in ("marker-cl1n", "Paracetamol", "Headache"):
        assert secret not in details


def test_clinic_visits_are_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert "clinic_visits" in APPEND_ONLY_TABLES
