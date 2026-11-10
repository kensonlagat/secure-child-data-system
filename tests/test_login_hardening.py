from datetime import datetime, timedelta
import pytest
from markupsafe import escape
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.blueprints.auth.routes import (
    INACTIVE_ACCOUNT_ERROR,
    PARENT_ACCOUNT_ERROR,
    PORTAL_MISMATCH_ERROR,
)
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.user import Role, User
from app.services.audit_service import log_action

GENERIC_ERROR = "Invalid credentials, or too many attempts. Try again later."
PORTAL_MISMATCH_TEXT = (
    "This account doesn't belong to the selected portal. "
    "Choose the other portal and try again."
)
PARENT_TEXT = "Parent accounts use the parent sign-in."


@pytest.fixture()
def app():
    application = create_app("testing")
    application.config.update(
        LOGIN_MAX_FAILURES=5,
        LOGIN_LOCKOUT_MINUTES=15,
        LOGIN_IP_MAX_FAILURES=20,
    )

    with application.app_context():
        db.create_all()
        roles = {}
        for role_name, institution_mode in (
            ("administrator", "both"),
            ("teacher", "school"),
            ("legal_officer", "childrens_home"),
            ("parent_guardian", "school"),
        ):
            role = Role(name=role_name, institution_mode=institution_mode)
            db.session.add(role)
            roles[role_name] = role
        db.session.flush()

        users = [
            User(
                email="teacher@example.com",
                full_name="Test Teacher",
                phone_number="+254700000001",
                password_hash=generate_password_hash("Teacher#2026"),
                role_id=roles["teacher"].id,
                is_active=True,
            ),
            User(
                email="legal@example.com",
                full_name="Test Legal Officer",
                phone_number="+254700000002",
                password_hash=generate_password_hash("Legal#2026"),
                role_id=roles["legal_officer"].id,
                is_active=True,
            ),
            User(
                email="admin@example.com",
                full_name="Test Administrator",
                phone_number="+254700000003",
                password_hash=generate_password_hash("Admin#2026"),
                role_id=roles["administrator"].id,
                is_active=True,
            ),
            User(
                email="parent@example.com",
                full_name="Test Parent",
                phone_number="+254700000004",
                password_hash=generate_password_hash("Parent#2026"),
                role_id=roles["parent_guardian"].id,
                is_active=True,
            ),
        ]
        db.session.add_all(users)
        db.session.commit()

    yield application

    with application.app_context():
        db.drop_all()


def post_login(client, email, password, portal="school", remote_addr="10.0.0.1"):
    return client.post(
        "/login",
        data={"email": email, "password": password, "portal": portal},
        environ_base={"REMOTE_ADDR": remote_addr},
    )


def assert_generic_failure(response):
    assert response.status_code == 401
    assert GENERIC_ERROR.encode() in response.data


def assert_denied_with(response, message):
    """Assert a 401 whose HTML body shows the given (auto-escaped) message."""
    assert response.status_code == 401
    assert str(escape(message)).encode() in response.data
    assert GENERIC_ERROR.encode() not in response.data


def login_failed_count(app, email):
    with app.app_context():
        return AuditLogEntry.query.filter_by(
            action="login_failed", attempted_identifier=email
        ).count()


def test_real_account_locks_after_maximum_failures_and_correct_password_is_refused(app):
    client = app.test_client()

    for _ in range(5):
        response = post_login(client, "teacher@example.com", "wrong-password")
        assert_generic_failure(response)

    response = post_login(client, "teacher@example.com", "Teacher#2026")
    assert_generic_failure(response)


def test_fake_account_locks_and_matches_real_account_response(app):
    client = app.test_client()

    for _ in range(5):
        response = post_login(
            client,
            "teacher@example.com",
            "wrong-password",
            remote_addr="10.0.0.1",
        )
    locked_real = post_login(
        client,
        "teacher@example.com",
        "Teacher#2026",
        remote_addr="10.0.0.1",
    )

    for _ in range(6):
        locked_fake = post_login(
            client,
            "nobody@example.com",
            "wrong-password",
            remote_addr="10.0.0.2",
        )

    assert_generic_failure(locked_real)
    assert_generic_failure(locked_fake)
    assert GENERIC_ERROR.encode() in locked_real.data
    assert GENERIC_ERROR.encode() in locked_fake.data


def test_lockout_lifts_after_configured_window(app):
    app.config["LOGIN_LOCKOUT_MINUTES"] = 1
    client = app.test_client()

    for _ in range(5):
        post_login(client, "teacher@example.com", "wrong-password")

    with app.app_context():
        for row in AuditLogEntry.query.filter_by(action="login_failed").all():
            row.timestamp = datetime.utcnow() - timedelta(minutes=2)
        db.session.commit()

    response = post_login(client, "teacher@example.com", "Teacher#2026")
    assert response.status_code == 302
    assert response.location.endswith("/school/records")


def test_inactive_account_messages_are_distinct_and_safe(app):
    with app.app_context():
        user = User.query.filter_by(email="teacher@example.com").one()
        user.is_active = False
        db.session.commit()

    client = app.test_client()
    inactive_correct = post_login(client, "teacher@example.com", "Teacher#2026")
    inactive_wrong = post_login(client, "teacher@example.com", "wrong-password")

    assert_denied_with(inactive_correct, INACTIVE_ACCOUNT_ERROR)
    assert_generic_failure(inactive_wrong)


def test_portal_binding_and_role_exemptions(app):
    client = app.test_client()

    teacher_home = post_login(
        client, "teacher@example.com", "Teacher#2026", portal="childrens_home"
    )
    legal_school = post_login(
        client, "legal@example.com", "Legal#2026", portal="school"
    )
    legal_home = post_login(
        client, "legal@example.com", "Legal#2026", portal="childrens_home"
    )
    admin_school = post_login(
        client, "admin@example.com", "Admin#2026", portal="school"
    )
    admin_home = post_login(
        client, "admin@example.com", "Admin#2026", portal="childrens_home"
    )
    parent_school = post_login(
        client, "parent@example.com", "Parent#2026", portal="school"
    )

    parent_home = post_login(
        client, "parent@example.com", "Parent#2026", portal="childrens_home"
    )

    assert_denied_with(teacher_home, PORTAL_MISMATCH_TEXT)
    assert_denied_with(legal_school, PORTAL_MISMATCH_TEXT)
    assert legal_home.status_code == 302
    assert legal_home.location.endswith("/home-mode/records")
    assert admin_school.status_code == 302
    assert admin_home.status_code == 302
    assert_denied_with(parent_school, PARENT_TEXT)
    assert_denied_with(parent_home, PARENT_TEXT)


def test_message_constants_match_agreed_wording():
    assert PORTAL_MISMATCH_ERROR == PORTAL_MISMATCH_TEXT
    assert PARENT_ACCOUNT_ERROR == PARENT_TEXT


def test_wrong_password_on_wrong_portal_stays_generic(app):
    # The portal message must only appear after the password verifies,
    # otherwise it would confirm the account exists.
    client = app.test_client()
    response = post_login(
        client, "teacher@example.com", "wrong-password", portal="childrens_home"
    )
    assert_generic_failure(response)
    assert login_failed_count(app, "teacher@example.com") == 1


def test_portal_mismatch_does_not_write_login_failed_or_lock(app):
    client = app.test_client()

    for _ in range(app.config["LOGIN_MAX_FAILURES"] + 2):
        response = post_login(
            client, "teacher@example.com", "Teacher#2026", portal="childrens_home"
        )
        assert_denied_with(response, PORTAL_MISMATCH_TEXT)

    assert login_failed_count(app, "teacher@example.com") == 0
    with app.app_context():
        assert (
            AuditLogEntry.query.filter_by(action="login_portal_mismatch").count()
            == app.config["LOGIN_MAX_FAILURES"] + 2
        )

    response = post_login(client, "teacher@example.com", "Teacher#2026", portal="school")
    assert response.status_code == 302
    assert response.location.endswith("/school/records")


def test_parent_on_staff_form_does_not_write_login_failed_or_lock(app):
    client = app.test_client()

    for _ in range(app.config["LOGIN_MAX_FAILURES"] + 2):
        response = post_login(client, "parent@example.com", "Parent#2026")
        assert_denied_with(response, PARENT_TEXT)

    assert login_failed_count(app, "parent@example.com") == 0
    # Still the parent message, not the lockout response.
    assert_denied_with(post_login(client, "parent@example.com", "Parent#2026"), PARENT_TEXT)


def test_inactive_account_does_not_write_login_failed_or_lock(app):
    with app.app_context():
        user = User.query.filter_by(email="teacher@example.com").one()
        user.is_active = False
        db.session.commit()

    client = app.test_client()
    for _ in range(app.config["LOGIN_MAX_FAILURES"] + 2):
        response = post_login(client, "teacher@example.com", "Teacher#2026")
        assert_denied_with(response, INACTIVE_ACCOUNT_ERROR)

    assert login_failed_count(app, "teacher@example.com") == 0
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="login_denied_inactive").count() == (
            app.config["LOGIN_MAX_FAILURES"] + 2
        )

    with app.app_context():
        user = User.query.filter_by(email="teacher@example.com").one()
        user.is_active = True
        db.session.commit()

    response = post_login(client, "teacher@example.com", "Teacher#2026")
    assert response.status_code == 302


def test_portal_mismatch_json_response(app):
    client = app.test_client()
    response = client.post(
        "/login",
        json={
            "email": "teacher@example.com",
            "password": "Teacher#2026",
            "portal": "childrens_home",
        },
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": PORTAL_MISMATCH_TEXT}


def test_ip_flood_guard_default_is_100():
    assert BaseConfig.LOGIN_IP_MAX_FAILURES == 100


def test_ip_flood_guard_blocks_after_configured_failures(app):
    app.config["LOGIN_IP_MAX_FAILURES"] = 3
    client = app.test_client()
    for n in range(3):
        post_login(client, f"nobody{n}@example.com", "x", remote_addr="10.9.9.9")

    # A correct password from the flooded IP is refused generically...
    assert_generic_failure(
        post_login(client, "teacher@example.com", "Teacher#2026", remote_addr="10.9.9.9")
    )
    # ...but the same account still signs in from another address.
    response = post_login(
        client, "teacher@example.com", "Teacher#2026", remote_addr="10.9.9.10"
    )
    assert response.status_code == 302


def test_attempted_identifier_is_truncated(app):
    long_identifier = "x" * 400
    with app.test_request_context("/login", environ_base={"REMOTE_ADDR": "10.0.0.3"}):
        log_action(
            action="login_failed",
            attempted_identifier=long_identifier,
            details="test",
        )

    with app.app_context():
        entry = AuditLogEntry.query.order_by(AuditLogEntry.id.desc()).first()
        assert len(entry.attempted_identifier) == 255
        assert entry.attempted_identifier == long_identifier[:255]
