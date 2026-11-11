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


# --- Adversarial self-review fixes (PR #46) ---


def test_non_admin_switch_attempt_is_audited(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")

    assert client.post("/switch-portal", data={"portal": "childrens_home"}).status_code == 403

    with app.app_context():
        entry = AuditLogEntry.query.filter_by(action="access_denied").one()
        assert entry.details == "Role check refused for endpoint auth.switch_portal"


def test_role_check_refusals_are_audited_on_any_route(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")

    assert client.get("/admin/dashboard").status_code == 403

    with app.app_context():
        entry = AuditLogEntry.query.filter_by(action="access_denied").one()
        assert "admin.dashboard" in entry.details


def test_rejected_switch_is_audited_without_the_raw_value(app):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    client.post("/switch-portal", data={"portal": "<script>everything</script>"})

    with app.app_context():
        entry = AuditLogEntry.query.filter_by(action="portal_switch_rejected").one()
        assert "everything" not in entry.details


@pytest.mark.parametrize("body", [["childrens_home"], "childrens_home"])
def test_switch_with_non_object_json_is_rejected_not_crashed(app, body):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = client.post("/switch-portal", json=body)

    assert response.status_code == 400
    assert active_portal(client) == "school"


# --- Lead review follow-up: bounded, safe and non-blocking refusal auditing ---

from datetime import datetime, timedelta  # noqa: E402


def _denied_rows(app):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action="access_denied").all()


def test_repeated_refusals_are_bounded_per_window(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")

    for _ in range(25):
        assert client.get("/admin/dashboard").status_code == 403

    assert len(_denied_rows(app)) == 1


def test_a_new_window_audits_again(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")
    client.get("/admin/dashboard")
    with app.app_context():
        for row in AuditLogEntry.query.filter_by(action="access_denied").all():
            row.timestamp = datetime.utcnow() - timedelta(seconds=61)  # test-only backdate
        db.session.commit()

    client.get("/admin/dashboard")

    assert len(_denied_rows(app)) == 2


def test_different_endpoints_are_audited_separately(app):
    client = app.test_client()
    sign_in(client, "teacher@example.com", "school")

    client.get("/admin/dashboard")
    client.get("/admin/anomaly-alerts")

    assert len(_denied_rows(app)) == 2


def test_unauthenticated_refusal_writes_safe_anonymous_identifier(app):
    client = app.test_client()

    response = client.post("/register", data={"email": "x@example.com"})

    assert response.status_code == 401
    rows = _denied_rows(app)
    assert len(rows) == 1
    assert rows[0].user_id is None
    assert rows[0].attempted_identifier == "anonymous"
    assert rows[0].details == "Unauthenticated request refused for endpoint auth.register"
    assert "x@example.com" not in (rows[0].details + rows[0].attempted_identifier)


def test_rotating_ip_addresses_does_not_lift_the_anonymous_bound(app):
    client = app.test_client()

    for i in range(30):
        client.post("/register", data={}, environ_base={"REMOTE_ADDR": f"203.0.113.{i}"})

    assert len(_denied_rows(app)) == 1


@pytest.mark.parametrize("signed_in, expected", [(True, 403), (False, 401)])
def test_refusal_happens_even_if_the_audit_write_fails(app, monkeypatch, signed_in, expected):
    client = app.test_client()
    path = "/admin/dashboard" if signed_in else "/register"
    if signed_in:
        sign_in(client, "teacher@example.com", "school")

    from app.services import audit_service

    def broken_log_action(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(audit_service, "log_action", broken_log_action)

    response = client.get(path) if signed_in else client.post(path, data={})

    assert response.status_code == expected
