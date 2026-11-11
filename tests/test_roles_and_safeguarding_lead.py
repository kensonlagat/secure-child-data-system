"""New oversight roles (#47) and the OTP-gated designated safeguarding lead flag."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.otp_event import OTPEvent
from app.models.user import Role, User
from app.services import access_service

PASSWORD = "Password#2026"


@pytest.fixture()
def sent_codes(monkeypatch):
    """Capture OTP codes instead of sending SMS."""
    codes = []

    def fake_send_sms(phone_number, message):
        codes.append(message.split("code is ")[1].split(".")[0])
        return {"SMSMessageData": {"Recipients": [{"statusCode": "101"}]}}

    monkeypatch.setattr("app.services.otp_service.send_sms", fake_send_sms)
    return codes


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
            ("principal", "school"),
            ("home_manager", "childrens_home"),
            ("parent_guardian", "school"),
        ):
            roles[name] = Role(name=name, institution_mode=mode)
            db.session.add(roles[name])
        db.session.flush()
        ids = {}
        for key, email, role in (
            ("admin", "admin@example.com", "administrator"),
            ("admin2", "admin2@example.com", "administrator"),
            ("principal", "principal@example.com", "principal"),
            ("manager", "manager@example.com", "home_manager"),
            ("parent", "parent@example.com", "parent_guardian"),
        ):
            user = User(
                email=email,
                full_name=f"Test {key}",
                phone_number="+254700000001",
                password_hash=generate_password_hash(PASSWORD),
                role_id=roles[role].id,
                is_active=True,
            )
            db.session.add(user)
            db.session.flush()
            ids[key] = user.id
        db.session.add_all([
            ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1),
                        institution_mode="school", class_assigned="Grade 6A"),
            ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1),
                        institution_mode="childrens_home", legal_status="in_state_care"),
        ])
        db.session.commit()
        application.config["IDS"] = ids
    yield application
    with application.app_context():
        db.drop_all()


def sign_in(client, email, portal):
    response = client.post("/login", data={"email": email, "password": PASSWORD, "portal": portal})
    assert response.status_code == 302


def actions(app, action):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=action).all()


def flag(app, key):
    with app.app_context():
        return db.session.get(User, app.config["IDS"][key]).is_safeguarding_lead


# --- New roles are fail-closed -------------------------------------------------


@pytest.mark.parametrize("key", ["principal", "manager"])
def test_new_roles_get_no_records_or_fields(app, key):
    with app.app_context():
        user = db.session.get(User, app.config["IDS"][key])
        assert access_service.get_accessible_records(user).count() == 0
        assert access_service.get_visible_fields(user) == []
        for record in ChildRecord.query.all():
            assert access_service.get_writable_fields(user, record) == []
            assert access_service.can_access_record(user, record) is False


@pytest.mark.parametrize(
    "email, portal, landing",
    [("principal@example.com", "school", "/school/records"),
     ("manager@example.com", "childrens_home", "/home-mode/records")],
)
def test_new_roles_sign_in_to_an_empty_safe_page(app, email, portal, landing):
    client = app.test_client()
    sign_in(client, email, portal)

    html = client.get(landing, headers={"Accept": "text/html"}).get_data(as_text=True)

    assert "No records to show." in html
    assert "School Child" not in html and "Home Child" not in html


def test_principal_cannot_sign_in_through_the_childrens_home_portal(app):
    response = app.test_client().post(
        "/login", data={"email": "principal@example.com", "password": PASSWORD, "portal": "childrens_home"}
    )
    assert response.status_code == 401


def test_new_users_default_to_not_safeguarding_lead(app):
    for key in ("admin", "principal", "manager"):
        assert flag(app, key) is False


# --- Safeguarding lead flag: OTP, audit, never on your own account ---------------


def request_change(client, user_id, value):
    return client.post(f"/admin/users/{user_id}/safeguarding-lead/request", json={"value": value})


def confirm_change(client, user_id, value, code):
    return client.post(
        f"/admin/users/{user_id}/safeguarding-lead/confirm", json={"value": value, "otp_code": code}
    )


def test_admin_sets_and_clears_the_flag_with_an_otp_and_it_is_audited(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    target = app.config["IDS"]["principal"]

    assert request_change(client, target, True).status_code == 201
    assert confirm_change(client, target, True, sent_codes[-1]).status_code == 200
    assert flag(app, "principal") is True

    assert request_change(client, target, False).status_code == 201
    assert confirm_change(client, target, False, sent_codes[-1]).status_code == 200
    assert flag(app, "principal") is False

    assert len(actions(app, "safeguarding_lead_change_requested")) == 2
    assert len(actions(app, "safeguarding_lead_set")) == 1
    assert len(actions(app, "safeguarding_lead_cleared")) == 1
    for entry in actions(app, "safeguarding_lead_set") + actions(app, "safeguarding_lead_cleared"):
        assert entry.target_record_id == target
        assert not any(code in (entry.details or "") for code in sent_codes)


def test_confirm_without_a_verified_otp_fails_and_is_audited(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    target = app.config["IDS"]["principal"]

    assert confirm_change(client, target, True, "123456").status_code == 400  # nothing requested
    request_change(client, target, True)
    wrong = "000000" if sent_codes[-1] != "000000" else "111111"
    assert confirm_change(client, target, True, wrong).status_code == 400

    assert flag(app, "principal") is False
    assert len(actions(app, "safeguarding_lead_change_otp_failed")) == 2


def test_otp_issued_to_another_admin_cannot_be_used(app, sent_codes):
    target = app.config["IDS"]["principal"]
    other = app.test_client()
    sign_in(other, "admin2@example.com", "school")
    request_change(other, target, True)
    code_for_admin2 = sent_codes[-1]

    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    assert confirm_change(client, target, True, code_for_admin2).status_code == 400
    assert flag(app, "principal") is False


def test_set_code_cannot_be_used_to_clear(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    target = app.config["IDS"]["principal"]
    with app.app_context():
        db.session.get(User, target).is_safeguarding_lead = True
        db.session.commit()

    request_change(client, target, False)  # a "clear" code
    clear_code = sent_codes[-1]
    with app.app_context():  # flag changed by someone else in the meantime
        db.session.get(User, target).is_safeguarding_lead = False
        db.session.commit()
    request_change(client, target, True)  # now a "set" code exists too

    # The clear code must not satisfy a set request.
    if clear_code != sent_codes[-1]:
        assert confirm_change(client, target, True, clear_code).status_code == 400
        assert flag(app, "principal") is False


def test_otp_is_single_use(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    target = app.config["IDS"]["principal"]
    request_change(client, target, True)
    code = sent_codes[-1]
    assert confirm_change(client, target, True, code).status_code == 200
    with app.app_context():
        db.session.get(User, target).is_safeguarding_lead = False
        db.session.commit()

    assert confirm_change(client, target, True, code).status_code == 400
    assert flag(app, "principal") is False


def test_expired_otp_is_rejected(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    target = app.config["IDS"]["principal"]
    request_change(client, target, True)
    with app.app_context():
        otp = OTPEvent.query.filter_by(action_context="safeguarding_lead_set").one()
        otp.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()

    assert confirm_change(client, target, True, sent_codes[-1]).status_code == 400
    assert flag(app, "principal") is False


def test_admin_cannot_change_their_own_flag(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")
    own = app.config["IDS"]["admin"]

    assert request_change(client, own, True).status_code == 403
    assert confirm_change(client, own, True, "123456").status_code == 403

    assert sent_codes == []
    assert flag(app, "admin") is False
    assert len(actions(app, "safeguarding_lead_change_denied_self")) == 2


@pytest.mark.parametrize("email, portal", [("principal@example.com", "school"), ("manager@example.com", "childrens_home")])
def test_non_admins_get_403_and_are_audited(app, sent_codes, email, portal):
    client = app.test_client()
    sign_in(client, email, portal)
    target = app.config["IDS"]["admin2"]

    assert request_change(client, target, True).status_code == 403
    assert sent_codes == []
    assert len(actions(app, "access_denied")) == 1


def test_parent_accounts_cannot_be_safeguarding_leads(app, sent_codes):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    assert request_change(client, app.config["IDS"]["parent"], True).status_code == 400
    assert sent_codes == []


@pytest.mark.parametrize("body", [{"value": "true"}, {"value": 1}, {}, ["value"]])
def test_value_must_be_a_real_boolean(app, sent_codes, body):
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = client.post(f"/admin/users/{app.config['IDS']['principal']}/safeguarding-lead/request", json=body)

    assert response.status_code == 400
    assert sent_codes == []


def test_sms_failure_is_audited_and_changes_nothing(app, monkeypatch):
    def broken_send(phone_number, message):
        raise RuntimeError("provider down")

    monkeypatch.setattr("app.services.otp_service.send_sms", broken_send)
    client = app.test_client()
    sign_in(client, "admin@example.com", "school")

    response = request_change(client, app.config["IDS"]["principal"], True)

    assert response.status_code == 502
    assert len(actions(app, "safeguarding_lead_change_otp_send_failed")) == 1
    assert flag(app, "principal") is False


# --- verify_otp is single use for every flow ---------------------------------


def test_verify_otp_rejects_an_already_verified_code(app, sent_codes):
    from app.services.otp_service import generate_otp, verify_otp

    with app.app_context():
        admin = db.session.get(User, app.config["IDS"]["admin"])
        otp = generate_otp(admin, "record_deletion", target_record_id=1)
        code = sent_codes[-1]
        assert verify_otp(otp, code) is True
        assert verify_otp(otp, code) is False
