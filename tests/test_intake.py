"""Admission and intake (#54), and the home manager's read-only record access."""

from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.intake import IntakeRecord
from app.models.user import Role, User
from app.services import access_service

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "social_worker": "childrens_home", "social_worker2": "childrens_home",
         "legal_officer": "childrens_home", "home_manager": "childrens_home", "teacher": "school"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}
INTAKE = {"referral_source": "police", "admission_date": (date.today() - timedelta(days=10)).isoformat(),
          "placement_reason": "Abandoned at the market (marker-1nt4)", "committal_order_reference": "CO/123/2026",
          "childrens_officer": "Officer Wanjiku"}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for key, mode in ROLES.items():
            role_name = "social_worker" if key.startswith("social_worker") else key
            role = Role.query.filter_by(name=role_name).first() or Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        mine = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           legal_status="in_state_care", caseload_worker_id=users["social_worker"].id,
                           medical_notes="Asthma")
        other = ChildRecord(full_name="Other Caseload", date_of_birth=date(2012, 1, 1),
                            institution_mode="childrens_home", caseload_worker_id=users["social_worker2"].id)
        school = ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([mine, other, school])
        db.session.commit()
        application.config.update(MINE=mine.id, OTHER=other.id, SCHOOL=school.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    role = "social_worker" if key.startswith("social_worker") else key
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def save(app, client, key="MINE", **overrides):
    return client.post(f"/intake/records/{app.config[key]}", data={**INTAKE, **overrides})


def intake_of(app, key="MINE"):
    with app.app_context():
        intake = IntakeRecord.query.filter_by(child_record_id=app.config[key]).first()
        if intake:
            db.session.expunge(intake)
        return intake


# --- Creating a home record requires an intake ---------------------------------------------------


def new_home_record(**extra):
    return {"full_name": "New Arrival", "date_of_birth": "2013-03-03", "institution_mode": "childrens_home", **extra}


def test_home_record_cannot_be_created_without_an_intake(app):
    admin = sign_in(app, "administrator")
    response = admin.post("/admin/records", json=new_home_record())
    assert response.status_code == 400 and "Intake required" in response.get_json()["error"]
    with app.app_context():
        assert ChildRecord.query.count() == 3


def test_home_record_with_intake_is_created_together(app):
    response = sign_in(app, "administrator").post("/admin/records", json=new_home_record(**INTAKE))
    assert response.status_code == 201
    with app.app_context():
        intake = IntakeRecord.query.filter_by(child_record_id=response.get_json()["id"]).one()
        assert intake.placement_reason == INTAKE["placement_reason"]
        assert AuditLogEntry.query.filter_by(action="intake_created").count() == 1


def test_school_records_need_no_intake(app):
    response = sign_in(app, "administrator").post("/admin/records", json={
        "full_name": "School New", "date_of_birth": "2015-01-01", "institution_mode": "school"})
    assert response.status_code == 201


# --- Who writes and who reads -------------------------------------------------------------------------


def test_social_worker_records_and_updates_intake_for_own_caseload(app):
    worker = sign_in(app, "social_worker")
    assert save(app, worker).status_code == 302
    assert intake_of(app).referral_source == "police"
    save(app, worker, referral_source="court")
    assert intake_of(app).referral_source == "court"
    with app.app_context():
        updated = AuditLogEntry.query.filter_by(action="intake_updated").one()
    assert updated.details == "Updated fields: referral_source"


@pytest.mark.parametrize("key, record_key", [("social_worker", "OTHER"), ("teacher", "MINE"),
                                            ("administrator", "SCHOOL"), ("home_manager", "SCHOOL")])
def test_out_of_scope_is_404(app, key, record_key):
    client = sign_in(app, key)
    assert client.get(f"/intake/records/{app.config[record_key]}").status_code == 404
    assert save(app, client, record_key).status_code == 404


@pytest.mark.parametrize("key", ["legal_officer", "home_manager"])
def test_legal_officer_and_home_manager_read_but_cannot_write(app, key):
    save(app, sign_in(app, "social_worker"))
    client = sign_in(app, key)
    html = client.get(f"/intake/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-1nt4" in html and 'name="placement_reason"' not in html
    assert save(app, client, referral_source="court").status_code == 403
    assert intake_of(app).referral_source == "police"


# --- Home manager record access ---------------------------------------------------------------------


def test_home_manager_reads_home_records_with_a_reduced_field_set(app):
    rows = sign_in(app, "home_manager").get("/home-mode/records", headers={"Accept": "application/json"}).get_json()["items"]
    assert {row["id"] for row in rows} == {app.config["MINE"], app.config["OTHER"]}
    assert all("medical_notes" not in row and "birth_certificate_number" not in row for row in rows)


def test_home_manager_writes_nothing(app):
    with app.app_context():
        manager = User.query.filter_by(email="home_manager@example.com").one()
        record = db.session.get(ChildRecord, app.config["MINE"])
        assert access_service.get_writable_fields(manager, record) == []
    response = sign_in(app, "home_manager").patch(f"/home-mode/records/{app.config['MINE']}",
                                                  json={"medical_notes": "x"})
    assert response.status_code in (400, 403)


def test_principal_still_has_no_general_record_access(app):
    with app.app_context():
        role = Role(name="principal", institution_mode="school")
        db.session.add(role)
        db.session.flush()
        principal = User(email="p@example.com", full_name="P", phone_number="+254700000009", password_hash="x",
                         role_id=role.id, is_active=True)
        db.session.add(principal)
        db.session.flush()
        assert access_service.get_accessible_records(principal).count() == 0


# --- Validation, encryption, audit -------------------------------------------------------------------


@pytest.mark.parametrize("bad", [{"referral_source": "unknown"}, {"admission_date": ""},
                                 {"admission_date": (date.today() + timedelta(days=1)).isoformat()},
                                 {"placement_reason": ""}, {"placement_reason": "x" * 1001},
                                 {"committal_order_reference": "x" * 61}])
def test_invalid_intake_is_refused(app, bad):
    save(app, sign_in(app, "social_worker"), **bad)
    assert intake_of(app) is None


def test_intake_text_is_ciphertext_at_rest(app):
    save(app, sign_in(app, "social_worker"))
    with app.app_context():
        row = db.session.execute(text("SELECT placement_reason, committal_order_reference, childrens_officer "
                                      "FROM intake_records")).one()
    stored = b"".join(bytes(value) for value in row)
    for plain in (b"marker-1nt4", b"CO/123/2026", b"Wanjiku"):
        assert plain not in stored


def test_every_view_and_change_is_audited_without_sensitive_text(app):
    worker = sign_in(app, "social_worker")
    worker.get(f"/intake/records/{app.config['MINE']}")
    save(app, worker)
    worker.get(f"/intake/records/{app.config['MINE']}")
    with app.app_context():
        actions = [row.action for row in AuditLogEntry.query.order_by(AuditLogEntry.id)]
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    assert actions.count("intake_viewed") == 2 and "intake_created" in actions
    for secret in ("marker-1nt4", "CO/123/2026", "Wanjiku"):
        assert secret not in details
