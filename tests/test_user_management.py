"""Administrator user management (#30)."""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.otp_event import OTPEvent
from app.models.user import Role, User

PASSWORD = "Password#2026"


@pytest.fixture()
def sms(monkeypatch):
    """Capture SMS (phone, code) pairs instead of sending."""
    sent = []

    def fake_send_sms(phone_number, message):
        sent.append((phone_number, message.split("code is ")[1].split(".")[0]))
        return {"SMSMessageData": {"Recipients": [{"statusCode": "101"}]}}

    monkeypatch.setattr("app.services.otp_service.send_sms", fake_send_sms)
    return sent


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        roles = {}
        for name, mode in (("administrator", "both"), ("teacher", "school"),
                           ("social_worker", "childrens_home"), ("parent_guardian", "school")):
            roles[name] = Role(name=name, institution_mode=mode)
            db.session.add(roles[name])
        db.session.flush()
        ids = {"roles": {k: v.id for k, v in roles.items()}}
        for key, email, role, phone in (
            ("admin", "admin@example.com", "administrator", "+254700000001"),
            ("teacher", "teacher@example.com", "teacher", "+254700000002"),
        ):
            user = User(email=email, full_name=f"Test {key}", phone_number=phone,
                        assigned_class="Grade 6A" if role == "teacher" else None,
                        password_hash=generate_password_hash(PASSWORD), role_id=roles[role].id, is_active=True)
            db.session.add(user)
            db.session.flush()
            ids[key] = user.id
        db.session.add(ChildRecord(full_name="Child", date_of_birth=date(2014, 1, 1),
                                   institution_mode="school", class_assigned="Grade 6A"))
        db.session.commit()
        application.config["IDS"] = ids
    yield application
    with application.app_context():
        db.drop_all()


def sign_in(client, email="admin@example.com", portal="school"):
    response = client.post("/login", data={"email": email, "password": PASSWORD, "portal": portal})
    assert response.status_code == 302
    return client


def audit(app, action):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=action).all()


def get_user(app, email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user is not None:
            db.session.expunge(user)
        return user


def new_staff(app, role="teacher", **overrides):
    data = {"full_name": "New Person", "email": "new@example.com", "phone_number": "+254711111111",
            "role_id": str(app.config["IDS"]["roles"][role]), "assigned_class": "Grade 5B"}
    data.update(overrides)
    return data


# --- Creating staff: SMS set-password code, nobody knows the password -----------


def test_new_staff_get_an_sms_code_and_set_their_own_password(app, sms, monkeypatch):
    monkeypatch.setattr("app.blueprints.auth.routes.MIN_RESPONSE_SECONDS", 0)
    admin = sign_in(app.test_client())

    response = admin.post("/admin/users", data=new_staff(app))

    assert response.status_code == 302
    created = get_user(app, "new@example.com")
    assert created.is_active is True
    assert created.assigned_class == "Grade 5B"
    assert sms[-1][0] == "+254711111111"  # code went to the new person, not the admin
    assert len(audit(app, "create_user")) == 1
    assert len(audit(app, "account_setup_code_sent")) == 1

    # The admin-chosen form never includes a password, and none was set that anyone knows.
    login = app.test_client().post("/login", data={"email": "new@example.com", "password": PASSWORD, "portal": "school"})
    assert login.status_code == 401

    # The person completes setup on the existing reset page with their code.
    reset = app.test_client().post("/reset-password", data={
        "email": "new@example.com", "otp_code": sms[-1][1], "new_password": "Their-own-pass-1"})
    assert reset.status_code == 302
    assert check_password_hash(get_user(app, "new@example.com").password_hash, "Their-own-pass-1")


def test_create_user_ignores_any_submitted_password(app, sms):
    admin = sign_in(app.test_client())
    admin.post("/admin/users", data=new_staff(app, password="Admin-chosen-1"))

    created = get_user(app, "new@example.com")
    assert not check_password_hash(created.password_hash, "Admin-chosen-1")


def test_sms_failure_on_create_is_audited_and_account_still_created(app, monkeypatch):
    def broken(phone_number, message):
        raise RuntimeError("down")

    monkeypatch.setattr("app.services.otp_service.send_sms", broken)
    admin = sign_in(app.test_client())

    admin.post("/admin/users", data=new_staff(app))

    assert get_user(app, "new@example.com") is not None
    assert len(audit(app, "account_setup_code_send_failed")) == 1


@pytest.mark.parametrize(
    "overrides, field",
    [({"email": "not-an-email"}, "email"), ({"email": "TEACHER@example.com"}, "email"),
     ({"phone_number": "0711111111"}, "phone_number"), ({"full_name": ""}, "full_name"),
     ({"role_id": "999"}, "role_id")],
)
def test_create_user_validation(app, sms, overrides, field):
    admin = sign_in(app.test_client())

    response = admin.post("/admin/users", data=new_staff(app, **overrides))

    assert response.status_code == 400
    assert get_user(app, overrides.get("email", "new@example.com")) is None or field == "email"
    assert sms == []


def test_parent_accounts_cannot_be_created_here(app, sms):
    admin = sign_in(app.test_client())
    response = admin.post("/admin/users", data=new_staff(app, role="parent_guardian"))
    assert response.status_code == 400
    assert get_user(app, "new@example.com") is None


def test_assigned_class_is_cleared_for_non_teachers(app, sms):
    admin = sign_in(app.test_client())
    admin.post("/admin/users", data=new_staff(app, role="social_worker"))
    assert get_user(app, "new@example.com").assigned_class is None


# --- New administrators need the acting admin's OTP ------------------------------


def test_new_admin_stays_inactive_until_the_acting_admin_confirms_an_otp(app, sms):
    admin = sign_in(app.test_client())

    response = admin.post("/admin/users", data=new_staff(app, role="administrator", email="boss@example.com"))
    new_admin = get_user(app, "boss@example.com")

    assert response.status_code == 302 and f"/admin/users/{new_admin.id}/grant-admin" in response.location
    assert new_admin.is_active is False
    assert sms[-1][0] == "+254700000001"  # the OTP went to the acting admin
    assert len(audit(app, "admin_grant_requested")) == 1

    wrong = "000000" if sms[-1][1] != "000000" else "111111"
    assert admin.post(f"/admin/users/{new_admin.id}/grant-admin", data={"otp_code": wrong}).status_code == 400
    assert get_user(app, "boss@example.com").is_active is False
    assert len(audit(app, "admin_grant_otp_failed")) == 1

    grant_code = [code for phone, code in sms if phone == "+254700000001"][-1]
    assert admin.post(f"/admin/users/{new_admin.id}/grant-admin", data={"otp_code": grant_code}).status_code == 302
    assert get_user(app, "boss@example.com").is_active is True
    assert len(audit(app, "admin_granted")) == 1
    assert sms[-1][0] == "+254711111111"  # then the new admin gets their set-password code


def test_grant_admin_otp_from_another_admin_is_rejected(app, sms):
    admin = sign_in(app.test_client())
    admin.post("/admin/users", data=new_staff(app, role="administrator", email="boss@example.com"))
    pending = get_user(app, "boss@example.com")
    with app.app_context():  # an OTP that belongs to someone else
        otp = OTPEvent.query.filter_by(action_context="grant_admin").one()
        otp.user_id = app.config["IDS"]["teacher"]
        db.session.commit()

    response = admin.post(f"/admin/users/{pending.id}/grant-admin", data={"otp_code": sms[-1][1]})

    assert response.status_code == 400
    assert get_user(app, "boss@example.com").is_active is False


def test_grant_admin_otp_is_single_use(app, sms):
    admin = sign_in(app.test_client())
    admin.post("/admin/users", data=new_staff(app, role="administrator", email="boss@example.com"))
    pending = get_user(app, "boss@example.com")
    code = sms[-1][1]
    admin.post(f"/admin/users/{pending.id}/grant-admin", data={"otp_code": code})
    admin.post(f"/admin/users/{pending.id}/deactivate")  # deactivate again (another admin is active)

    response = admin.post(f"/admin/users/{pending.id}/grant-admin", data={"otp_code": code})

    assert response.status_code == 400
    assert get_user(app, "boss@example.com").is_active is False


def test_reactivating_an_admin_needs_a_fresh_otp(app, sms):
    admin = sign_in(app.test_client())
    admin.post("/admin/users", data=new_staff(app, role="administrator", email="boss@example.com"))
    boss = get_user(app, "boss@example.com")
    grant_code = [code for phone, code in sms if phone == "+254700000001"][-1]
    admin.post(f"/admin/users/{boss.id}/grant-admin", data={"otp_code": grant_code})
    admin.post(f"/admin/users/{boss.id}/deactivate")
    assert get_user(app, "boss@example.com").is_active is False

    response = admin.post(f"/admin/users/{boss.id}/reactivate")

    assert f"/admin/users/{boss.id}/grant-admin" in response.location
    assert get_user(app, "boss@example.com").is_active is False


def test_role_cannot_be_changed_to_administrator_by_edit(app, sms):
    admin = sign_in(app.test_client())
    teacher_id = app.config["IDS"]["teacher"]

    response = admin.post(f"/admin/users/{teacher_id}/edit", data={
        "full_name": "Test teacher", "phone_number": "+254700000002",
        "role_id": str(app.config["IDS"]["roles"]["administrator"])})

    assert response.status_code == 400
    assert get_user(app, "teacher@example.com").role_id == app.config["IDS"]["roles"]["teacher"]


# --- Own account, last admin, admin phone ------------------------------------------


@pytest.mark.parametrize("path", ["edit", "deactivate", "reactivate", "grant-admin"])
def test_admins_cannot_manage_their_own_account(app, sms, path):
    admin = sign_in(app.test_client())
    own = app.config["IDS"]["admin"]

    response = admin.post(f"/admin/users/{own}/{path}", data={"full_name": "x", "otp_code": "123456"})

    assert response.status_code == 403
    assert get_user(app, "admin@example.com").is_active is True
    assert len(audit(app, "user_change_denied_self")) == 1


def test_last_active_admin_cannot_be_deactivated(app, sms, monkeypatch):
    # Through the routes this can't happen (the actor is always another active admin), so
    # the guard is defence in depth; force the count to 1 to prove it refuses and audits.
    with app.app_context():
        db.session.add(User(email="second@example.com", full_name="Second", phone_number="+254700000009",
                            password_hash=generate_password_hash(PASSWORD),
                            role_id=app.config["IDS"]["roles"]["administrator"], is_active=True))
        db.session.commit()
        second_id = User.query.filter_by(email="second@example.com").one().id
    monkeypatch.setattr("app.blueprints.admin.user_routes._active_admin_count", lambda: 1)
    admin = sign_in(app.test_client())

    admin.post(f"/admin/users/{second_id}/deactivate")

    assert get_user(app, "second@example.com").is_active is True
    assert len(audit(app, "user_deactivation_refused")) == 1


def test_admin_phone_cannot_be_changed_here(app, sms):
    with app.app_context():
        db.session.add(User(email="second@example.com", full_name="Second", phone_number="+254700000009",
                            password_hash=generate_password_hash(PASSWORD),
                            role_id=app.config["IDS"]["roles"]["administrator"], is_active=True))
        db.session.commit()
        second_id = User.query.filter_by(email="second@example.com").one().id
    admin = sign_in(app.test_client())

    response = admin.post(f"/admin/users/{second_id}/edit", data={
        "full_name": "Second", "phone_number": "+254799999999",
        "role_id": str(app.config["IDS"]["roles"]["administrator"])})

    assert response.status_code == 400
    assert get_user(app, "second@example.com").phone_number == "+254700000009"


def test_edit_is_audited_with_field_names_only(app, sms):
    admin = sign_in(app.test_client())
    teacher_id = app.config["IDS"]["teacher"]

    admin.post(f"/admin/users/{teacher_id}/edit", data={
        "full_name": "Renamed", "phone_number": "+254722222222",
        "role_id": str(app.config["IDS"]["roles"]["teacher"]), "assigned_class": "Grade 7C"})

    entry = audit(app, "user_updated")[0]
    assert entry.details == "Updated fields: full_name, phone_number, assigned_class"
    assert "+254722222222" not in entry.details


# --- Deactivation ends sessions immediately (user_loader) --------------------------


def test_deactivated_user_is_signed_out_on_the_next_request(app, sms):
    teacher = sign_in(app.test_client(), "teacher@example.com")
    assert teacher.get("/school/records", headers={"Accept": "text/html"}).status_code == 200

    admin = sign_in(app.test_client())
    admin.post(f"/admin/users/{app.config['IDS']['teacher']}/deactivate")

    response = teacher.get("/school/records", headers={"Accept": "text/html"})
    assert response.status_code == 302
    assert "/login" in response.location
    assert len(audit(app, "user_deactivated")) == 1


def test_user_loader_rejects_inactive_accounts(app):
    from app import load_user

    with app.app_context():
        assert load_user(str(app.config["IDS"]["teacher"])) is not None
        teacher = db.session.get(User, app.config["IDS"]["teacher"])
        teacher.is_active = False
        db.session.commit()
        assert load_user(str(app.config["IDS"]["teacher"])) is None


def test_reactivated_staff_can_sign_in_again(app, sms):
    admin = sign_in(app.test_client())
    teacher_id = app.config["IDS"]["teacher"]
    admin.post(f"/admin/users/{teacher_id}/deactivate")
    admin.post(f"/admin/users/{teacher_id}/reactivate")

    assert get_user(app, "teacher@example.com").is_active is True
    assert len(audit(app, "user_reactivated")) == 1
    sign_in(app.test_client(), "teacher@example.com")


# --- Access ----------------------------------------------------------------------------


@pytest.mark.parametrize("method, path", [("get", "/admin/users"), ("get", "/admin/users/new"),
                                          ("post", "/admin/users"), ("post", "/admin/users/1/deactivate")])
def test_non_admins_are_refused(app, sms, method, path):
    teacher = sign_in(app.test_client(), "teacher@example.com")

    response = getattr(teacher, method)(path)

    assert response.status_code == 403
    assert get_user(app, "admin@example.com").is_active is True


def test_register_endpoint_is_retired(app):
    admin = sign_in(app.test_client())
    response = admin.post("/register", json={"email": "x@example.com", "password": "Chosen#2026",
                                             "full_name": "X", "phone_number": "+254700000003", "role_id": 2})
    assert response.status_code in (404, 405)
    assert get_user(app, "x@example.com") is None


def test_users_page_lists_staff_and_hides_actions_on_own_row(app):
    admin = sign_in(app.test_client())
    html = admin.get("/admin/users").get_data(as_text=True)

    assert "teacher@example.com" in html
    assert "Your own account" in html
    assert f'data-safeguarding-user="{app.config["IDS"]["admin"]}"' not in html
    assert "<script>" not in html  # no inline script
