"""Route-level regression tests for PATCH /school/records/<id>.

Issue #40: a smoke test once reported HTTP 500 when the admin edit form sent an
empty string for a Boolean or date field. It was not reproducible, but these
tests pin the expected behaviour: an empty string is rejected with 400 and never
reaches the database.
"""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.blueprints.school_mode import routes as school_routes
from app.config import BaseConfig
from app.models.child_record import ChildRecord
from app.models.user import Role, User


@pytest.fixture()
def app(monkeypatch):
    # Encrypted columns read the key at use time; give tests a throwaway key.
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    # No real SMS from tests, even if an update were ever accepted.
    monkeypatch.setattr(school_routes, "send_sms", lambda *args, **kwargs: None)

    application = create_app("testing")
    with application.app_context():
        db.create_all()
        admin_role = Role(name="administrator", institution_mode="both")
        db.session.add(admin_role)
        db.session.flush()
        admin = User(
            email="admin@example.com",
            full_name="Test Administrator",
            phone_number="+254700000003",
            password_hash=generate_password_hash("Admin#2026"),
            role_id=admin_role.id,
            is_active=True,
        )
        record = ChildRecord(
            full_name="Test Child",
            date_of_birth=date(2014, 1, 15),
            institution_mode="school",
            class_assigned="Grade 6A",
            guardian_contact="+254700111223",
        )
        db.session.add_all([admin, record])
        db.session.commit()
        application.config["TEST_ADMIN_ID"] = admin.id
        application.config["TEST_RECORD_ID"] = record.id

    yield application

    with application.app_context():
        db.drop_all()


@pytest.fixture()
def admin_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.config["TEST_ADMIN_ID"])
        session["_fresh"] = True
    return client


@pytest.mark.parametrize(
    "field_name, expected_error",
    [
        ("is_deleted", "Request contained field(s) this role cannot update."),
        ("date_of_birth", "date_of_birth cannot be blank."),
        ("caseload_worker_id", "caseload_worker_id must be null or an integer."),
    ],
)
def test_empty_string_is_rejected_with_400(app, admin_client, field_name, expected_error):
    record_id = app.config["TEST_RECORD_ID"]

    response = admin_client.patch(f"/school/records/{record_id}", json={field_name: ""})

    assert response.status_code == 400
    assert response.get_json()["error"] == expected_error
    if field_name == "is_deleted":
        assert response.get_json()["rejected_fields"] == ["is_deleted"]

    with app.app_context():
        record = db.session.get(ChildRecord, record_id)
        assert record.is_deleted is False
        assert record.deleted_at is None
        assert record.date_of_birth == date(2014, 1, 15)
        assert record.caseload_worker_id is None
