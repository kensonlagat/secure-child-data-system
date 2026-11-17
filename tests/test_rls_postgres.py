"""Row-level security (#19), on PostgreSQL. Required for this feature: set TEST_POSTGRES_URL to a
DISPOSABLE database reachable as a superuser (the test resets its public schema).

Two NOLOGIN roles are created: an owner (owns the tables, BYPASSRLS, like cds_owner) and an app
role (no BYPASSRLS, like cds_app). The app connects as the app role, so every query is subject
to the policies from the real migration.
"""

import importlib.util
import os
import re
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash

POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="needs TEST_POSTGRES_URL (a disposable PostgreSQL database)")

OWNER, APP_ROLE = "cds_rls_test_owner", "cds_rls_test_app"
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "c5f1e8a3b7d2_add_row_level_security.py"
PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
         "social_worker": "childrens_home", "legal_officer": "childrens_home", "home_manager": "childrens_home",
         "parent_guardian": "school"}


def _with_role(url, role):
    return {"connect_args": {"options": f"-c role={role}"}}


def _rls_sql():
    spec = importlib.util.spec_from_file_location("rls_migration", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.FUNCTIONS, module.POLICIES


@pytest.fixture(scope="module")
def pg_app():
    from app.config import BaseConfig, TestingConfig

    saved = (BaseConfig.FIELD_ENCRYPTION_KEY, TestingConfig.SQLALCHEMY_DATABASE_URI,
             getattr(TestingConfig, "SQLALCHEMY_ENGINE_OPTIONS", None))
    BaseConfig.FIELD_ENCRYPTION_KEY = Fernet.generate_key().decode()
    admin_engine = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
        for role, extra in ((OWNER, "BYPASSRLS"), (APP_ROLE, "NOBYPASSRLS")):
            if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first():
                conn.execute(text(f"CREATE ROLE {role} NOLOGIN {extra}"))
            conn.execute(text(f"ALTER ROLE {role} {extra}"))
        conn.execute(text(f"GRANT ALL ON SCHEMA public TO {OWNER}"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))

    from app import create_app, db

    # Build the schema as the owner, so the owner owns every table (as in production).
    TestingConfig.SQLALCHEMY_DATABASE_URI = POSTGRES_URL
    TestingConfig.SQLALCHEMY_ENGINE_OPTIONS = _with_role(POSTGRES_URL, OWNER)
    owner_app = create_app("testing")
    functions, policies = _rls_sql()
    with owner_app.app_context():
        db.create_all()
        with db.engine.begin() as conn:
            conn.execute(text(functions))
            conn.execute(text(policies))
            from app.services.key_derivation import derive_subkey
            conn.execute(text("INSERT INTO rls_context_key (id, key) VALUES (1, :k)"),
                         {"k": derive_subkey("rls-context")})
            conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}"))
            conn.execute(text(f"REVOKE ALL ON rls_context_key FROM {APP_ROLE}"))
            conn.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}"))
            for function in ("app_context_valid()",
                             "audit_stats(text, timestamp, integer, boolean, text, text, text, text, integer, boolean)",
                             "parent_has_active_link(integer)"):
                conn.execute(text(f"GRANT EXECUTE ON FUNCTION {function} TO {APP_ROLE}"))
        ids = _seed(db)
        db.session.remove()
        db.engine.dispose()

    # The app under test connects as the app role.
    TestingConfig.SQLALCHEMY_ENGINE_OPTIONS = _with_role(POSTGRES_URL, APP_ROLE)
    app = create_app("testing")
    app.config.update(IDS=ids)
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    with admin_engine.connect() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    admin_engine.dispose()
    BaseConfig.FIELD_ENCRYPTION_KEY, TestingConfig.SQLALCHEMY_DATABASE_URI = saved[0], saved[1]
    if saved[2] is None:
        del TestingConfig.SQLALCHEMY_ENGINE_OPTIONS
    else:
        TestingConfig.SQLALCHEMY_ENGINE_OPTIONS = saved[2]


def _seed(db):
    """Runs as the owner (BYPASSRLS). Returns ids by name."""
    from app.models.child_record import ChildRecord
    from app.models.guardian_link import GuardianLink
    from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass
    from app.models.user import Role, User

    users = {}
    for name, mode in ROLES.items():
        role = Role(name=name, institution_mode=mode)
        db.session.add(role)
        db.session.flush()
        extra = {"email": None, "login_phone": "+254711000001"} if name == "parent_guardian" \
            else {"email": f"{name}@example.com"}
        users[name] = User(full_name=name, phone_number="+254711000001", role_id=role.id, is_active=True,
                           password_hash=generate_password_hash(PASSWORD), **extra)
        db.session.add(users[name])
    users["other_worker"] = User(full_name="other", email="other_worker@example.com", phone_number="+254711000002",
                                 role_id=users["social_worker"].role_id, is_active=True,
                                 password_hash=generate_password_hash(PASSWORD))
    db.session.add(users["other_worker"])
    db.session.flush()

    def child(name, mode, **extra):
        record = ChildRecord(full_name=name, date_of_birth=date(2014, 1, 1), institution_mode=mode, **extra)
        db.session.add(record)
        db.session.flush()
        return record

    kids = {
        "in_class": child("In Class", "school"),
        "other_class": child("Other Class", "school"),
        "school_archived": child("Archived", "school", is_archived=True),
        "school_deleted": child("Deleted", "school", is_deleted=True),
        "home_mine": child("Home Mine", "childrens_home", caseload_worker_id=users["social_worker"].id),
        "home_other": child("Home Other", "childrens_home", caseload_worker_id=users["other_worker"].id),
    }
    c6a = SchoolClass(name="Grade 6", stream="A", academic_year=2026, is_active=True)
    c7b = SchoolClass(name="Grade 7", stream="B", academic_year=2026, is_active=True)
    db.session.add_all([c6a, c7b])
    db.session.flush()
    db.session.add_all([
        Enrolment(child_record_id=kids["in_class"].id, class_id=c6a.id, started_on=date(2026, 1, 1), reason="enrolled"),
        Enrolment(child_record_id=kids["school_archived"].id, class_id=c6a.id, started_on=date(2026, 1, 1),
                  reason="enrolled"),
        Enrolment(child_record_id=kids["other_class"].id, class_id=c7b.id, started_on=date(2026, 1, 1),
                  reason="enrolled"),
        ClassTeacherAssignment(class_id=c6a.id, user_id=users["teacher"].id),
        GuardianLink(child_record_id=kids["in_class"].id, guardian_user_id=users["parent_guardian"].id,
                     relationship="mother", identity_document_type="national_id", status="active",
                     created_by=users["administrator"].id),
        GuardianLink(child_record_id=kids["other_class"].id, guardian_user_id=users["parent_guardian"].id,
                     relationship="mother", identity_document_type="national_id", status="pending",
                     created_by=users["administrator"].id),
    ])
    db.session.commit()
    return {"users": {k: v.id for k, v in users.items()}, "kids": {k: v.id for k, v in kids.items()}}


def _visible(app, user_key=None, statement="SELECT id FROM child_records"):
    from flask import session

    from app import db
    with app.test_request_context("/"):
        if user_key:
            session["_user_id"] = str(app.config["IDS"]["users"][user_key])
        rows = db.session.execute(text(statement)).all()
        db.session.commit()
        db.session.remove()
    return rows


def _ids(app, *names):
    return {app.config["IDS"]["kids"][name] for name in names}


# The union of every access_service path, per role (get_accessible_records plus the pickup,
# missing-alert, attendance and report-card lookups). Archived and deleted rows only for admins.
EXPECTED = {
    "administrator": ("in_class", "other_class", "school_archived", "school_deleted", "home_mine", "home_other"),
    "teacher": ("in_class",),
    "school_nurse": ("in_class", "other_class"),
    "principal": ("in_class", "other_class"),
    "social_worker": ("home_mine", "home_other"),  # any home child: the missing-alert rule (#60)
    "legal_officer": ("home_mine", "home_other"),
    "home_manager": ("home_mine", "home_other"),
    "parent_guardian": ("in_class",),  # active link only; the pending one gives nothing
}


@pytest.mark.parametrize("role", sorted(EXPECTED))
def test_an_unscoped_select_as_cds_app_returns_only_the_users_scope(pg_app, role):
    visible = {row[0] for row in _visible(pg_app, role)}
    assert visible == _ids(pg_app, *EXPECTED[role])


@pytest.mark.parametrize("role", ["teacher", "school_nurse", "social_worker", "parent_guardian"])
def test_rls_rows_include_everything_access_service_returns(pg_app, role):
    from app import db
    from app.models.user import User
    from app.services.access_service import get_accessible_records
    from flask import session

    with pg_app.test_request_context("/"):
        session["_user_id"] = str(pg_app.config["IDS"]["users"][role])
        user = db.session.get(User, pg_app.config["IDS"]["users"][role])
        scoped = {record.id for record in get_accessible_records(user).all()}
        db.session.remove()
    assert scoped <= {row[0] for row in _visible(pg_app, role)}


def test_no_context_sees_nothing_and_cannot_insert_audit_rows(pg_app):
    from app import db
    with pg_app.app_context():
        with db.engine.connect() as conn:  # a plain connection: no session hook, no context
            assert conn.execute(text("SELECT count(*) FROM child_records")).scalar() == 0
            with pytest.raises(Exception, match="row-level security"):
                conn.execute(text("INSERT INTO audit_log_entries (action, attempted_identifier, is_synthetic) "
                                  "VALUES ('probe', 'probe', true)"))


def _set(conn, values):
    for name, value in values.items():
        conn.execute(text("SELECT set_config(:n, :v, true)"), {"n": name, "v": value})


def test_forged_tampered_and_expired_contexts_see_nothing(pg_app):
    from app import db
    from app.rls import context_values
    admin_id = str(pg_app.config["IDS"]["users"]["administrator"])
    teacher_id = str(pg_app.config["IDS"]["users"]["teacher"])
    with pg_app.app_context():
        with db.engine.connect() as conn:
            def count(values):
                with conn.begin():
                    _set(conn, values)
                    return conn.execute(text("SELECT count(*) FROM child_records")).scalar()

            good = context_values(admin_id, "administrator", "both")
            assert count(good) == 6
            assert count({**good, "app.context_sig": "0" * 64}) == 0                       # forged signature
            assert count({**context_values(teacher_id, "teacher", "school"), "app.role": "administrator"}) == 0
            assert count({**good, "app.user_id": teacher_id}) == 0                          # tampered user
            assert count(context_values(admin_id, "administrator", "both",
                                        issued_at=datetime.utcnow().timestamp() - 301)) == 0  # older than 5 minutes


def test_the_context_does_not_survive_into_the_next_transaction(pg_app):
    from app import db
    from app.rls import context_values
    with pg_app.app_context():
        with db.engine.connect() as conn:
            with conn.begin():
                _set(conn, context_values("", "system", ""))
                assert conn.execute(text("SELECT count(*) FROM child_records")).scalar() == 6
            assert conn.execute(text("SELECT count(*) FROM child_records")).scalar() == 0


def test_python_and_database_hmac_agree(pg_app):
    import hashlib
    import hmac as py_hmac

    from app import db
    with pg_app.app_context():
        key, message = b"k" * 32, b"1|teacher|school|1700000000"
        db_value = db.session.execute(text("SELECT encode(app_hmac_sha256(:k, :m), 'hex')"),
                                      {"k": key, "m": message}).scalar()
        db.session.remove()
    assert db_value == py_hmac.new(key, message, hashlib.sha256).hexdigest()


def test_audit_rows_are_readable_by_administrators_only_but_counting_still_works(pg_app):
    from app import db
    from app.services.audit_service import audit_stats, log_action
    from flask import session

    with pg_app.test_request_context("/"):
        log_action(attempted_identifier="unknown:probe", action="rls_probe", details="probe")
        assert audit_stats("rls_probe", identifier="unknown:probe")[0] == 1  # anonymous: count, no rows
        assert db.session.execute(text("SELECT count(*) FROM audit_log_entries")).scalar() == 0
        db.session.remove()
    assert _visible(pg_app, "teacher", "SELECT count(*) FROM audit_log_entries")[0][0] == 0
    assert _visible(pg_app, "administrator", "SELECT count(*) FROM audit_log_entries")[0][0] >= 1


def test_login_lockout_still_works_for_anonymous_visitors_under_rls(pg_app):
    client = pg_app.test_client()
    for _ in range(5):
        assert client.post("/login", data={"email": "teacher@example.com", "password": "wrong-password",
                                           "portal": "school"}).status_code == 401
    response = client.post("/login", data={"email": "teacher@example.com", "password": PASSWORD, "portal": "school"})
    assert response.status_code == 401  # locked: counted through audit_stats()


def test_a_signed_in_teacher_sees_only_their_class_through_the_app(pg_app):
    client = pg_app.test_client()
    assert client.post("/login", data={"email": "principal@example.com", "password": PASSWORD,
                                       "portal": "school"}).status_code == 302
    in_class, other = pg_app.config["IDS"]["kids"]["in_class"], pg_app.config["IDS"]["kids"]["other_class"]
    assert client.get(f"/pickup/records/{in_class}").status_code in (200, 302)
    assert client.get(f"/pickup/records/{other}").status_code in (200, 302)


def test_parent_sign_in_works_under_rls(pg_app, monkeypatch):
    from app.blueprints.parent import routes as parent_routes
    sent = []
    monkeypatch.setattr("app.services.otp_service.send_sms", lambda phone, message: sent.append(message))
    monkeypatch.setattr(parent_routes, "MIN_RESPONSE_SECONDS", 0.0)
    client = pg_app.test_client()
    client.post("/parent/login", data={"phone": "+254711000001"})
    assert len(sent) == 1  # parent_has_active_link() answered for the anonymous visitor
    code = re.search(r"\b(\d{6})\b", sent[0]).group(1)
    assert client.post("/parent/verify", data={"code": code}).status_code == 302
    page = client.get("/parent/", headers={"Accept": "application/json"}).get_json()
    assert [item["id"] for item in page["items"]] == [pg_app.config["IDS"]["kids"]["in_class"]]


def test_cli_commands_see_data_only_through_the_system_context(pg_app):
    from app import db
    from app.rls import system_context
    with pg_app.app_context():
        assert db.session.execute(text("SELECT count(*) FROM child_records")).scalar() == 0
        db.session.commit()
        with system_context():
            assert db.session.execute(text("SELECT count(*) FROM child_records")).scalar() == 6
            db.session.commit()
        db.session.remove()


def test_child_linked_tables_follow_the_child_scope(pg_app):
    from app import db
    from app.models.consent import ConsentRecord
    from app.rls import system_context
    kids = pg_app.config["IDS"]["kids"]
    with pg_app.app_context():
        with system_context():
            db.session.commit()
            for key in ("in_class", "other_class"):
                db.session.add(ConsentRecord(child_record_id=kids[key], consent_type="photo", status="given",
                                             effective_date=date(2026, 1, 1), guardian_name="G",
                                             recorded_by=pg_app.config["IDS"]["users"]["administrator"]))
            db.session.commit()
        db.session.remove()
    rows = {row[0] for row in _visible(pg_app, "teacher", "SELECT child_record_id FROM consent_records")}
    assert rows == {kids["in_class"]}
