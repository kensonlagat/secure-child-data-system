"""Emails are case-insensitive everywhere: stored lower-case, matched with lower() (#74)."""

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app, db
from app.models.audit_log import AuditLogEntry
from app.models.user import Role, User


@pytest.fixture()
def sms(monkeypatch):
    sent = []

    def fake_send_sms(phone_number, message):
        sent.append((phone_number, message.split("code is ")[1].split(".")[0]))
        return {"SMSMessageData": {"Recipients": [{"statusCode": "101"}]}}

    monkeypatch.setattr("app.services.otp_service.send_sms", fake_send_sms)
    monkeypatch.setattr("app.blueprints.auth.routes.MIN_RESPONSE_SECONDS", 0)
    return sent


@pytest.fixture()
def app():
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        role = Role(name="teacher", institution_mode="school")
        db.session.add(role)
        db.session.flush()
        db.session.add(User(email="  Teacher@Example.COM ", full_name="T", phone_number="+254700000001",
                            password_hash=generate_password_hash("Password#2026"), role_id=role.id))
        db.session.commit()
    yield application
    with application.app_context():
        db.drop_all()


def test_emails_are_stored_trimmed_and_lower_case(app):
    with app.app_context():
        assert User.query.one().email == "teacher@example.com"


@pytest.mark.parametrize("typed", ["teacher@example.com", "TEACHER@EXAMPLE.COM", " Teacher@Example.com "])
def test_forgot_password_finds_the_account_whatever_the_case(app, sms, typed):
    response = app.test_client().post("/forgot-password", data={"email": typed})

    assert response.status_code == 200
    assert len(sms) == 1 and sms[0][0] == "+254700000001"


def test_reset_password_works_with_a_different_case(app, sms):
    client = app.test_client()
    client.post("/forgot-password", data={"email": "TEACHER@example.com"})

    response = client.post("/reset-password", data={
        "email": "Teacher@EXAMPLE.com", "otp_code": sms[-1][1], "new_password": "New-password-1"})

    assert response.status_code == 302
    with app.app_context():
        assert check_password_hash(User.query.one().password_hash, "New-password-1")


def test_login_still_case_insensitive(app):
    response = app.test_client().post(
        "/login", data={"email": "TEACHER@EXAMPLE.COM", "password": "Password#2026", "portal": "school"})
    assert response.status_code == 302


def test_unknown_identifier_hash_matches_across_case_and_endpoints(app, sms):
    client = app.test_client()
    client.post("/login", data={"email": "Ghost@Example.com", "password": "x"})
    client.post("/forgot-password", data={"email": "ghost@EXAMPLE.com"})

    with app.app_context():
        identifiers = {
            row.attempted_identifier
            for row in AuditLogEntry.query.filter(
                AuditLogEntry.action.in_(["login_failed", "password_reset_requested_unknown_identifier"])
            )
        }
    assert len(identifiers) == 1
    assert identifiers.pop().startswith("unknown:")


def test_create_admin_cli_refuses_a_case_duplicate(app):
    with app.app_context():
        db.session.add(Role(name="administrator", institution_mode="both"))
        db.session.commit()
        result = app.test_cli_runner().invoke(args=[
            "create-admin", "--email", "TEACHER@example.com", "--password", "Password#2026",
            "--full-name", "Dup", "--phone", "+254700000009"])

    assert result.exit_code != 0
    assert "already exists" in result.output
    with app.app_context():
        assert User.query.count() == 1
