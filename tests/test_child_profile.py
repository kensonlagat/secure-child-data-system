"""Fuller child profile (#49a): gender, birth certificate number, learner UPI, allergies."""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.encryption import UNREADABLE
from app.models.user import Role, User
from app.services import access_service
from class_helpers import put_in_class

PASSWORD = "Password#2026"
NEW_FIELDS = ("gender", "birth_certificate_number", "learner_upi", "allergies")
ENCRYPTED = ("birth_certificate_number", "learner_upi", "allergies")

# The approved table (design note on #49).
EXPECTED_VISIBLE = {
    "administrator": {"gender", "birth_certificate_number", "learner_upi", "allergies"},
    "teacher": {"gender", "allergies"},
    "school_nurse": {"gender", "allergies"},
    "social_worker": {"gender", "birth_certificate_number", "allergies"},
    "legal_officer": {"birth_certificate_number"},
    "principal": set(),
    "home_manager": set(),
    "parent_guardian": set(),
}
EXPECTED_WRITABLE_SCHOOL = {
    "administrator": {"gender", "birth_certificate_number", "learner_upi", "allergies"},
    "teacher": set(),
    "school_nurse": {"allergies"},
    "social_worker": set(),  # school record: outside a social worker's scope
    "legal_officer": set(),
    "principal": set(),
    "home_manager": set(),
    "parent_guardian": set(),
}
MODES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "social_worker": "childrens_home",
         "legal_officer": "childrens_home", "principal": "school", "home_manager": "childrens_home",
         "parent_guardian": "school"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for role_name, mode in MODES.items():
            role = Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[role_name] = User(email=f"{role_name}@example.com", full_name=role_name, phone_number="+254700000001",
                                    password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[role_name])
        db.session.flush()
        school = ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1), institution_mode="school",
                             gender="female", birth_certificate_number="BC/2014-0042", learner_upi="UPI123ABC",
                             allergies="Peanuts (marker-a11e)")
        home = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           legal_status="in_state_care", caseload_worker_id=users["social_worker"].id,
                           birth_certificate_number="BC/2012-0007", allergies="None known")
        db.session.add_all([school, home])
        db.session.flush()
        put_in_class("Grade 6A", children=[school], teachers=[users["teacher"]])
        db.session.commit()
        application.config.update(SCHOOL=school.id, HOME=home.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, role_name):
    client = app.test_client()
    response = client.post("/login", data={"email": f"{role_name}@example.com", "password": PASSWORD,
                                           "portal": PORTAL[MODES[role_name]]})
    assert response.status_code == 302
    return client


def record(app, key="SCHOOL"):
    with app.app_context():
        found = db.session.get(ChildRecord, app.config[key])
        db.session.expunge(found)
        return found


# --- Visibility and writability matrix -------------------------------------------------


@pytest.mark.parametrize("role_name", sorted(MODES))
def test_visible_profile_fields_match_the_approved_table(app, role_name):
    with app.app_context():
        user = User.query.filter_by(email=f"{role_name}@example.com").one()
        visible = set(access_service.get_visible_fields(user)) & set(NEW_FIELDS)
    assert visible == EXPECTED_VISIBLE[role_name]


@pytest.mark.parametrize("role_name", sorted(MODES))
def test_writable_profile_fields_on_a_school_record_match_the_approved_table(app, role_name):
    with app.app_context():
        user = User.query.filter_by(email=f"{role_name}@example.com").one()
        school = db.session.get(ChildRecord, app.config["SCHOOL"])
        writable = set(access_service.get_writable_fields(user, school)) & set(NEW_FIELDS)
    assert writable == EXPECTED_WRITABLE_SCHOOL[role_name]


def test_social_worker_writes_allergies_on_their_own_caseload(app):
    with app.app_context():
        worker = User.query.filter_by(email="social_worker@example.com").one()
        home = db.session.get(ChildRecord, app.config["HOME"])
        assert set(access_service.get_writable_fields(worker, home)) & set(NEW_FIELDS) == {"allergies"}


def test_learner_upi_is_never_writable_on_a_childrens_home_record(app):
    with app.app_context():
        admin = User.query.filter_by(email="administrator@example.com").one()
        home = db.session.get(ChildRecord, app.config["HOME"])
        assert "learner_upi" not in access_service.get_writable_fields(admin, home)
    response = sign_in(app, "administrator").patch(f"/home-mode/records/{app.config['HOME']}",
                                                   json={"learner_upi": "UPI999"})
    assert response.status_code == 400


def test_teacher_list_shows_gender_and_allergies_but_not_identity_numbers(app):
    rows = sign_in(app, "teacher").get("/school/records", headers={"Accept": "application/json"}).get_json()
    assert rows[0]["allergies"] == "Peanuts (marker-a11e)" and rows[0]["gender"] == "female"
    assert "birth_certificate_number" not in rows[0] and "learner_upi" not in rows[0]


def test_legal_officer_sees_birth_certificate_but_no_health_fields(app):
    rows = sign_in(app, "legal_officer").get("/home-mode/records", headers={"Accept": "application/json"}).get_json()
    assert rows[0]["birth_certificate_number"] == "BC/2012-0007"
    assert "allergies" not in rows[0] and "gender" not in rows[0]


def test_teacher_cannot_patch_profile_fields(app):
    response = sign_in(app, "teacher").patch(f"/school/records/{app.config['SCHOOL']}", json={"allergies": "None"})
    assert response.status_code == 400
    assert record(app).allergies == "Peanuts (marker-a11e)"


def test_nurse_can_update_allergies_and_it_is_audited_without_the_value(app):
    response = sign_in(app, "school_nurse").patch(f"/school/records/{app.config['SCHOOL']}",
                                                  json={"allergies": "Peanuts, penicillin (marker-b22f)"})
    assert response.status_code == 200
    assert record(app).allergies == "Peanuts, penicillin (marker-b22f)"
    with app.app_context():
        details = " ".join(r.details or "" for r in AuditLogEntry.query.filter_by(action="update_record"))
    assert "allergies" in details and "marker-b22f" not in details


# --- Validation ------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["BC/2020-7", "123456", "A-1/2", "X" * 30])
def test_birth_certificate_accepts_letters_digits_slash_and_dash(app, value):
    response = sign_in(app, "administrator").patch(f"/school/records/{app.config['SCHOOL']}",
                                                   json={"birth_certificate_number": value})
    assert response.status_code == 200
    assert record(app).birth_certificate_number == value


@pytest.mark.parametrize("field, value", [
    ("birth_certificate_number", "X" * 31),
    ("birth_certificate_number", "BC 2014"),
    ("birth_certificate_number", "BC#2014"),
    ("learner_upi", "UPI-123"),
    ("learner_upi", "U" * 21),
    ("gender", "other"),
    ("allergies", "a" * 501),
])
def test_invalid_profile_values_are_refused(app, field, value):
    before = getattr(record(app), field)
    response = sign_in(app, "administrator").patch(f"/school/records/{app.config['SCHOOL']}", json={field: value})
    assert response.status_code == 400
    assert getattr(record(app), field) == before


def test_gender_can_be_cleared_back_to_not_recorded_yet(app):
    response = sign_in(app, "administrator").patch(f"/school/records/{app.config['SCHOOL']}", json={"gender": ""})
    assert response.status_code == 200
    assert record(app).gender is None


# --- Encryption at rest --------------------------------------------------------------------


@pytest.mark.parametrize("column", ENCRYPTED)
def test_profile_fields_are_ciphertext_at_rest(app, column):
    with app.app_context():
        stored = db.session.execute(text(f"SELECT {column} FROM child_records WHERE id = :id"),
                                    {"id": app.config["SCHOOL"]}).scalar()
    assert stored is not None
    assert getattr(record(app), column).encode() not in bytes(stored)


def test_equal_birth_certificate_numbers_store_differently(app):
    with app.app_context():
        db.session.get(ChildRecord, app.config["HOME"]).birth_certificate_number = "BC/2014-0042"
        db.session.commit()
        stored = db.session.execute(text("SELECT birth_certificate_number FROM child_records ORDER BY id")).scalars().all()
    assert stored[0] != stored[1]


def test_tampered_profile_value_reads_as_unreadable_without_a_500(app):
    with app.app_context():
        stored = bytearray(db.session.execute(text("SELECT allergies FROM child_records WHERE id = :id"),
                                              {"id": app.config["SCHOOL"]}).scalar())
        middle = len(stored) // 2  # a fully significant base64 character, never padding bits
        stored[middle] = ord("A") if stored[middle] != ord("A") else ord("B")
        db.session.execute(text("UPDATE child_records SET allergies = :v WHERE id = :id"),
                           {"v": bytes(stored), "id": app.config["SCHOOL"]})
        db.session.commit()
    response = sign_in(app, "teacher").get("/school/records", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.get_json()[0]["allergies"] == UNREADABLE


# --- Creating a record with profile fields ----------------------------------------------------


def test_create_record_accepts_profile_fields(app):
    response = sign_in(app, "administrator").post("/admin/records", json={
        "full_name": "New Child", "date_of_birth": "2015-02-02", "institution_mode": "school",
        "gender": "male", "birth_certificate_number": "BC/2015-1", "learner_upi": "UPI42", "allergies": "Dust"})
    assert response.status_code == 201
    with app.app_context():
        created = db.session.get(ChildRecord, response.get_json()["id"])
        assert (created.gender, created.birth_certificate_number, created.learner_upi, created.allergies) == (
            "male", "BC/2015-1", "UPI42", "Dust")


def test_create_record_refuses_invalid_profile_values_and_upi_for_home_records(app):
    admin = sign_in(app, "administrator")
    bad = admin.post("/admin/records", json={"full_name": "X", "date_of_birth": "2015-02-02",
                                             "institution_mode": "school", "gender": "unknown"})
    home_upi = admin.post("/admin/records", json={"full_name": "Y", "date_of_birth": "2015-02-02",
                                                  "institution_mode": "childrens_home", "learner_upi": "UPI1"})
    assert bad.status_code == 400 and home_upi.status_code == 400
    with app.app_context():
        assert ChildRecord.query.count() == 2


def test_edit_form_offers_a_gender_select(app):
    html = sign_in(app, "administrator").get(f"/school/records/{app.config['SCHOOL']}/edit").get_data(as_text=True)
    assert '<select id="field-gender" name="gender">' in html
    assert 'name="learner_upi"' in html
    home_html = sign_in(app, "administrator").get(f"/home-mode/records/{app.config['HOME']}/edit").get_data(as_text=True)
    assert 'name="learner_upi"' not in home_html
