"""Administrators see one portal at a time and can switch without signing out.

The separation is display only: these tests also check that the server's access rules
and data are unchanged (decision on issue #45: hide, don't block).
"""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.user import Role, User


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        roles = {}
        for name, mode in (
            ("administrator", "both"),
            ("teacher", "school"),
            ("social_worker", "childrens_home"),
        ):
            roles[name] = Role(name=name, institution_mode=mode)
            db.session.add(roles[name])
        db.session.flush()

        def add_user(email, role, assigned_class=None):
            user = User(
                email=email,
                full_name=f"Test {role}",
                phone_number="+254700000001",
                assigned_class=assigned_class,
                password_hash=generate_password_hash("Password#2026"),
                role_id=roles[role].id,
                is_active=True,
            )
            db.session.add(user)
            return user

        add_user("admin@example.com", "administrator")
        add_user("teacher@example.com", "teacher", "Grade 6A")
        worker = add_user("worker@example.com", "social_worker")
        db.session.flush()
        school = ChildRecord(
            full_name="School Child",
            date_of_birth=date(2014, 1, 15),
            institution_mode="school",
            class_assigned="Grade 6A",
            guardian_contact="+254700111223",
        )
        home = ChildRecord(
            full_name="Home Child",
            date_of_birth=date(2012, 4, 4),
            institution_mode="childrens_home",
            legal_status="in_state_care",
            caseload_worker_id=worker.id,
        )
        db.session.add_all([school, home])
        db.session.commit()
        application.config["SCHOOL_RECORD_ID"] = school.id
        application.config["HOME_RECORD_ID"] = home.id
    yield application
    with application.app_context():
        db.drop_all()


def sign_in(client, email, portal):
    response = client.post(
        "/login", data={"email": email, "password": "Password#2026", "portal": portal}
    )
    assert response.status_code == 302
    return response


def active_portal(client):
    with client.session_transaction() as session:
        return session.get("active_portal")


@pytest.mark.parametrize("portal", ["school", "childrens_home"])
def test_login_remembers_the_chosen_portal(app, portal):
    client = app.test_client()
    sign_in(client, "admin@example.com", portal)
    assert active_portal(client) == portal


def test_admin_in_school_portal_sees_only_school_pages(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    html = client.get("/admin/dashboard").get_data(as_text=True)

    assert 'href="/school/records"' in html
    assert 'href="/home-mode/' not in html
    assert "Pending legal status requests" not in html
    assert "School portal" in html
    assert "Switch to Children&#39;s Home" in html


def test_admin_in_childrens_home_portal_sees_only_home_pages(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "childrens_home")

    html = client.get("/admin/dashboard").get_data(as_text=True)

    assert 'href="/home-mode/records"' in html
    assert 'href="/home-mode/legal-status/requests"' in html
    assert 'href="/school/records"' not in html
    assert "Pending legal status requests" in html
    assert "Switch to School" in html


def test_admin_can_switch_portal_without_signing_out_and_it_is_audited(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = client.post("/switch-portal", data={"portal": "childrens_home"})

    assert response.status_code == 302
    assert response.location.endswith("/admin/dashboard")
    assert active_portal(client) == "childrens_home"
    html = client.get("/admin/dashboard").get_data(as_text=True)
    assert 'href="/home-mode/records"' in html
    with app.app_context():
        entry = AuditLogEntry.query.filter_by(action="portal_switch").one()
        assert entry.details == "Switched portal from school to childrens_home"


def test_switch_portal_rejects_invalid_portal(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = client.post("/switch-portal", data={"portal": "everything"})

    assert response.status_code == 302
    assert active_portal(client) == "school"
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="portal_switch").count() == 0


def test_switch_portal_is_get_proof(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    assert client.get("/switch-portal?portal=childrens_home").status_code == 405
    assert active_portal(client) == "school"


def test_non_admin_cannot_switch_portal(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")

    response = client.post("/switch-portal", data={"portal": "childrens_home"})

    assert response.status_code == 403
    assert active_portal(client) == "school"


def test_staff_always_see_their_own_mode_whatever_the_session_says(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")
    with client.session_transaction() as session:
        session["active_portal"] = "childrens_home"

    html = client.get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)

    assert "School portal" in html
    assert "Switch to" not in html


def test_logout_clears_active_portal(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "childrens_home")

    client.get("/logout")

    assert active_portal(client) is None


def test_signed_in_visit_to_login_redirects_to_landing_page(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = client.get("/login")

    assert response.status_code == 302
    assert response.location.endswith("/admin/dashboard")


def test_school_list_hides_childrens_home_columns_but_data_is_unchanged(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    html = client.get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert "Legal status" not in html
    assert "Caseload worker id" not in html
    assert "Guardian contact" in html

    # Hide only: the JSON API still returns what access_service allows for the role.
    rows = client.get("/school/records", headers={"Accept": "application/json"}).get_json()
    assert "legal_status" in rows[0]


def test_home_list_hides_school_columns(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "childrens_home")

    html = client.get("/home-mode/records", headers={"Accept": "text/html"}).get_data(as_text=True)

    assert "Legal status" in html
    assert "Guardian contact" not in html
    assert "Class assigned" not in html


def test_edit_form_shows_only_fields_for_the_record_mode(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    school_html = client.get(f"/school/records/{app.config['SCHOOL_RECORD_ID']}/edit").get_data(as_text=True)
    home_html = client.get(f"/home-mode/records/{app.config['HOME_RECORD_ID']}/edit").get_data(as_text=True)

    assert 'name="guardian_contact"' in school_html
    assert 'name="caseload_worker_id"' not in school_html
    assert 'name="caseload_worker_id"' in home_html
    assert 'name="guardian_contact"' not in home_html
    assert 'name="class_assigned"' not in home_html


def test_admin_viewing_other_mode_by_url_is_not_blocked(app):
    # Decision on #45: hide, don't block. An admin in the School portal can still open
    # children's home records by URL; the page says which portal they are in.
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = client.get("/home-mode/records", headers={"Accept": "text/html"})

    assert response.status_code == 200
    assert "You are in the School portal" in response.get_data(as_text=True)


def test_create_form_uses_the_active_portal(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "childrens_home")

    html = client.get("/admin/records/new").get_data(as_text=True)

    assert '<input type="hidden" name="institution_mode" value="childrens_home">' in html
    assert 'name="caseload_worker_id"' in html
    assert 'name="class_assigned"' not in html
