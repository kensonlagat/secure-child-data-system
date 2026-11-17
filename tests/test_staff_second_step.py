"""Staff second sign-in step (#68): the one-time code comes after the password, is bound to the
half-signed-in user, and only its verification signs the session in."""

import re
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig, TestingConfig
from app.models.audit_log import AuditLogEntry
from app.models.otp_event import OTPEvent
from app.models.user import Role, User

PASSWORD = "Password#2026"
PROTECTED = "/admin/dashboard"


@pytest.fixture()
def sms(monkeypatch):
    sent = []
    monkeypatch.setattr("app.services.otp_service.send_sms", lambda phone, message: sent.append((phone, message)))
    return sent


@pytest.fixture()
def app(monkeypatch, sms):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(TestingConfig, "STAFF_SECOND_STEP_REQUIRED", True)
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        admin_role = Role(name="administrator", institution_mode="both")
        teacher_role = Role(name="teacher", institution_mode="school")
        db.session.add_all([admin_role, teacher_role])
        db.session.flush()
        for email, role, phone in (("admin@example.com", admin_role, "+254700000001"),
                                   ("other@example.com", admin_role, "+254700000002"),
                                   ("teacher@example.com", teacher_role, "+254700000003")):
            db.session.add(User(email=email, full_name=email.split("@")[0], phone_number=phone,
                                password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True))
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def password_step(client, email="admin@example.com", portal="school"):
    return client.post("/login", data={"email": email, "password": PASSWORD, "portal": portal})


def last_code(sms):
    return re.search(r"\b(\d{6})\b", sms[-1][1]).group(1)


def wrong(code):
    return f"{(int(code) + 1) % 1000000:06d}"


def actions(app, name):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=name).count()


def is_signed_in(client):
    return client.get(PROTECTED).status_code == 200


# --- The password alone does not sign in ---------------------------------------------------------


def test_password_sends_a_code_and_does_not_sign_in(app, sms):
    client = app.test_client()
    response = password_step(client)
    assert response.status_code == 302 and response.headers["Location"].endswith("/login/verify")
    assert sms[-1][0] == "+254700000001"
    assert not is_signed_in(client)
    assert actions(app, "login") == 0
    assert actions(app, "login_code_sent") == 1
    with app.app_context():
        otp = OTPEvent.query.one()
        assert otp.action_context == "staff_login"
        assert otp.code_hash != last_code(sms)  # stored hashed
        assert otp.expires_at <= datetime.utcnow() + timedelta(minutes=5, seconds=5)


def test_skipping_the_second_step_by_going_straight_to_protected_urls_fails(app, sms):
    client = app.test_client()
    password_step(client)
    for url in (PROTECTED, "/admin/users", "/school/records", "/admin/archive", "/admin/classes"):
        response = client.get(url)
        assert response.status_code in (302, 401), url
        if response.status_code == 302:
            assert "/login" in response.headers["Location"]
    assert client.post("/switch-portal", data={"portal": "childrens_home"}).status_code in (302, 401)


def test_the_right_code_signs_in_with_a_fresh_session_and_no_remember_me(app, sms):
    client = app.test_client()
    password_step(client)
    with client.session_transaction() as half:
        half_session = dict(half)
    response = client.post("/login/verify", data={"code": last_code(sms)})
    assert response.status_code == 302
    assert is_signed_in(client)
    assert actions(app, "login") == 1
    with client.session_transaction() as full:
        assert "pending_staff_login" not in full
        assert full.get("session_nonce")
        assert full.get("_fresh") is True
        assert "pending_staff_login" in half_session
    assert client.get_cookie("remember_token") is None


def test_remember_me_does_not_skip_the_second_step(app, sms):
    client = app.test_client()
    client.post("/login", data={"email": "admin@example.com", "password": PASSWORD, "portal": "school",
                                "remember": "on", "remember_me": "on"})
    assert client.get_cookie("remember_token") is None
    assert not is_signed_in(client)


# --- Code rules: hashed, 5 minutes, 5 attempts, single use, bound to the user ------------------


def test_an_expired_code_fails_and_restarts_sign_in(app, sms):
    client = app.test_client()
    password_step(client)
    with app.app_context():
        otp = OTPEvent.query.one()
        otp.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
    response = client.post("/login/verify", data={"code": last_code(sms)})
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    assert not is_signed_in(client)


def test_five_wrong_codes_use_up_the_code(app, sms):
    client = app.test_client()
    password_step(client)
    code = last_code(sms)
    for _ in range(4):
        assert client.post("/login/verify", data={"code": wrong(code)}).status_code == 401
    response = client.post("/login/verify", data={"code": wrong(code)})
    assert response.status_code == 302  # attempts used up: back to the password step
    assert client.post("/login/verify", data={"code": code}).status_code == 302
    assert not is_signed_in(client)


def test_wrong_codes_count_towards_the_account_lockout(app, sms):
    client = app.test_client()
    password_step(client)
    code = last_code(sms)
    for _ in range(5):
        client.post("/login/verify", data={"code": wrong(code)})
    assert actions(app, "login_failed") == 5
    # Locked: even the right password no longer sends a code.
    sent_before = len(sms)
    response = password_step(client)
    assert response.status_code == 401
    assert len(sms) == sent_before
    assert actions(app, "login_blocked") == 1


def test_mixed_password_and_code_failures_share_one_lockout(app, sms):
    client = app.test_client()
    for _ in range(3):
        client.post("/login", data={"email": "admin@example.com", "password": "wrong-pass", "portal": "school"})
    password_step(client)
    code = last_code(sms)
    client.post("/login/verify", data={"code": wrong(code)})
    response = client.post("/login/verify", data={"code": wrong(code)})
    assert response.status_code == 302  # the fifth failure locks the account and restarts
    assert client.post("/login/verify", data={"code": code}).status_code == 302
    assert not is_signed_in(client)


def test_a_used_code_and_its_half_signed_in_session_cannot_be_reused(app, sms):
    client = app.test_client()
    password_step(client)
    code = last_code(sms)
    with client.session_transaction() as half:
        half_session = dict(half)
    assert client.post("/login/verify", data={"code": code}).status_code == 302
    attacker = app.test_client()
    with attacker.session_transaction() as stolen:
        stolen.update(half_session)
    response = attacker.post("/login/verify", data={"code": code})
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    assert not is_signed_in(attacker)
    assert actions(app, "login_code_rejected") == 1


def test_a_half_signed_in_session_cannot_be_pointed_at_another_users_code(app, sms):
    client = app.test_client()
    password_step(client, "admin@example.com")
    with client.session_transaction() as half:
        admin_pending = dict(half["pending_staff_login"])
    other = app.test_client()
    password_step(other, "other@example.com")
    other_code = last_code(sms)
    with app.app_context():
        other_otp = OTPEvent.query.filter_by(user_id=User.query.filter_by(email="other@example.com").one().id).one()
        other_otp_id = other_otp.id
    with client.session_transaction() as half:
        half["pending_staff_login"] = {**admin_pending, "otp_id": other_otp_id}
    response = client.post("/login/verify", data={"code": other_code})
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    assert not is_signed_in(client)


def test_a_code_from_another_flow_cannot_finish_sign_in(app, sms):
    from app.services.otp_service import generate_otp
    client = app.test_client()
    password_step(client)
    with app.app_context():
        user = User.query.filter_by(email="admin@example.com").one()
        foreign = generate_otp(user, "record_delete", target_record_id=user.id)
        foreign_id = foreign.id
    foreign_code = last_code(sms)
    with client.session_transaction() as half:
        half["pending_staff_login"] = {**half["pending_staff_login"], "otp_id": foreign_id}
    response = client.post("/login/verify", data={"code": foreign_code})
    assert response.status_code == 302
    assert not is_signed_in(client)


def test_the_verify_page_without_a_password_step_sends_you_back(app, sms):
    client = app.test_client()
    assert client.get("/login/verify").status_code == 302
    assert client.post("/login/verify", data={"code": "123456"}).status_code == 302
    assert not is_signed_in(client)


def test_deactivation_during_the_second_step_stops_sign_in(app, sms):
    client = app.test_client()
    password_step(client)
    with app.app_context():
        User.query.filter_by(email="admin@example.com").one().is_active = False
        db.session.commit()
    assert client.post("/login/verify", data={"code": last_code(sms)}).status_code == 302
    assert not is_signed_in(client)


def test_portal_binding_still_applies_before_any_code_is_sent(app, sms):
    client = app.test_client()
    response = password_step(client, "teacher@example.com", portal="childrens_home")
    assert response.status_code == 401
    assert sms == []


def test_logout_clears_a_half_signed_in_session(app, sms):
    client = app.test_client()
    password_step(client)
    client.get("/logout")
    assert client.post("/login/verify", data={"code": last_code(sms)}).status_code == 302
    assert not is_signed_in(client)


def test_the_code_never_appears_in_audit_rows(app, sms):
    client = app.test_client()
    password_step(client)
    code = last_code(sms)
    client.post("/login/verify", data={"code": wrong(code)})
    client.post("/login/verify", data={"code": code})
    with app.app_context():
        for row in AuditLogEntry.query.all():
            assert code not in (row.details or "") and wrong(code) not in (row.details or "")


def test_the_app_refuses_to_start_with_the_second_step_off_outside_testing(monkeypatch):
    from app.config import DevelopmentConfig
    monkeypatch.setattr(DevelopmentConfig, "STAFF_SECOND_STEP_REQUIRED", False)
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(RuntimeError, match="STAFF_SECOND_STEP_REQUIRED"):
        create_app("development")
