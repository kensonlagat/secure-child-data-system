"""CSRF with protection switched on (hard rule 8). The rest of the suite disables it."""

import re
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
TOKEN_INPUT = re.compile(r'name="csrf_token" value="([^"]+)"')
TOKEN_META = re.compile(r'name="csrf-token" content="([^"]+)"')


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    application.config["WTF_CSRF_ENABLED"] = True
    with application.app_context():
        db.create_all()
        admin_role = Role(name="administrator", institution_mode="both")
        db.session.add(admin_role)
        db.session.flush()
        db.session.add(User(email="admin@example.com", full_name="Admin", phone_number="+254700000001",
                            password_hash=generate_password_hash(PASSWORD), role_id=admin_role.id, is_active=True))
        record = ChildRecord(full_name="Child", date_of_birth=date(2014, 1, 1), institution_mode="school",
                             guardian_contact="+254711111111")
        db.session.add(record)
        db.session.commit()
        application.config["RECORD"] = record.id
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def login_token(client):
    return TOKEN_INPUT.search(client.get("/login").get_data(as_text=True)).group(1)


def signed_in(app):
    client = app.test_client()
    response = client.post("/login", data={"email": "admin@example.com", "password": PASSWORD, "portal": "school",
                                           "csrf_token": login_token(client)})
    assert response.status_code == 302 and "/login" not in response.headers["Location"]
    return client


def page_token(client):
    html = client.get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    return TOKEN_META.search(html).group(1)


def guardian_contact(app):
    with app.app_context():
        return db.session.get(ChildRecord, app.config["RECORD"]).guardian_contact


def test_login_without_a_token_is_refused(app):
    client = app.test_client()
    response = client.post("/login", data={"email": "admin@example.com", "password": PASSWORD, "portal": "school"})

    assert response.status_code == 302
    assert "/admin" not in response.headers["Location"]
    assert client.get("/admin/dashboard").status_code in (302, 401)  # still signed out


def test_login_with_a_token_works(app):
    signed_in(app)


def test_patch_without_a_token_is_refused_and_audited(app):
    client = signed_in(app)

    response = client.patch(f"/school/records/{app.config['RECORD']}", json={"guardian_contact": "+254722222222"})

    assert response.status_code == 400
    assert guardian_contact(app) == "+254711111111"
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="csrf_failure").count() == 1


def test_patch_with_the_page_token_works(app):
    client = signed_in(app)
    token = page_token(client)

    response = client.patch(f"/school/records/{app.config['RECORD']}", json={"guardian_contact": "+254722222222"},
                            headers={"X-CSRFToken": token})

    assert response.status_code == 200
    assert guardian_contact(app) == "+254722222222"


def test_token_from_another_session_is_refused(app):
    other = signed_in(app)
    foreign_token = page_token(other)
    client = signed_in(app)

    response = client.patch(f"/school/records/{app.config['RECORD']}", json={"guardian_contact": "+254733333333"},
                            headers={"X-CSRFToken": foreign_token})

    assert response.status_code == 400
    assert guardian_contact(app) == "+254711111111"


def test_form_post_without_a_token_creates_nothing(app):
    client = signed_in(app)

    client.post("/admin/records", data={"full_name": "Forged", "date_of_birth": "2015-01-01",
                                        "institution_mode": "school"})

    with app.app_context():
        assert ChildRecord.query.count() == 1


def test_every_post_form_on_key_pages_carries_a_token(app):
    client = signed_in(app)
    for path in ("/admin/records/new", "/admin/users/new", "/admin/classes"):
        html = client.get(path).get_data(as_text=True)
        forms = re.findall(r"<form[^>]*method=\"post\"[^>]*>(.*?)</form>", html, flags=re.S | re.I)
        assert forms, path
        assert all('name="csrf_token"' in form for form in forms), path
