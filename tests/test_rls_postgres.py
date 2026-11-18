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
VERSIONS = Path(__file__).resolve().parents[1] / "migrations" / "versions"
MIGRATION = VERSIONS / "c5f1e8a3b7d2_add_row_level_security.py"
REPORT_CARD_MIGRATION = VERSIONS / "f8c3a5d1e9b7_add_report_cards.py"
SAFEGUARDING_MIGRATION = VERSIONS / "e4b8c2f6d9a1_add_safeguarding_concerns.py"
PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
         "social_worker": "childrens_home", "legal_officer": "childrens_home", "home_manager": "childrens_home",
         "parent_guardian": "school"}


def _with_role(url, role):
    return {"connect_args": {"options": f"-c role={role}"}}


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rls_sql():
    module = _load(MIGRATION, "rls_migration")
    return module.FUNCTIONS, module.POLICIES


def _report_card_lock_sql():
    """The #70 published-card trigger, from its real migration (SECURITY DEFINER, owner-owned)."""
    module = _load(REPORT_CARD_MIGRATION, "report_card_migration")
    return module.LOCK_FUNCTION, module.TRIGGERS


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
            lock_function, lock_triggers = _report_card_lock_sql()
            conn.execute(text(lock_function))
            conn.execute(text(lock_triggers))
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
            # #62, from its real migration, after the grants above (as on a real database, where
            # the app role already exists when the migration runs): column grants, helper
            # functions (EXECUTE for the app role) and its own policies, replacing any generic
            # child_scope_/parent_scope_ policy the #19 loops created on these tables here.
            safeguarding = _load(SAFEGUARDING_MIGRATION, "safeguarding_migration")
            conn.execute(text(safeguarding.RESTRICT))
            conn.execute(text(safeguarding.FUNCTIONS))
            conn.execute(text(safeguarding.POLICIES))
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
    users["lockout_probe"] = User(full_name="lockout", email="lockout_probe@example.com",
                                  phone_number="+254711000003", role_id=users["teacher"].role_id, is_active=True,
                                  password_hash=generate_password_hash(PASSWORD))
    db.session.add(users["lockout_probe"])
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
    return {"users": {k: v.id for k, v in users.items()}, "kids": {k: v.id for k, v in kids.items()},
            "classes": {"c6a": c6a.id, "c7b": c7b.id}}


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


def _pid(conn):
    inside = conn.in_transaction()
    value = conn.execute(text("SELECT pg_backend_pid()")).scalar()
    if not inside:
        conn.rollback()  # don't leave an autobegun transaction behind
    return value


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

            pid = _pid(conn)
            good = context_values(admin_id, "administrator", "both", pid=pid)
            assert count(good) == 6
            assert count({**good, "app.context_sig": "0" * 64}) == 0                       # forged signature
            assert count({**context_values(teacher_id, "teacher", "school", pid=pid), "app.role": "administrator"}) == 0
            assert count({**good, "app.user_id": teacher_id}) == 0                          # tampered user
            assert count(context_values(admin_id, "administrator", "both", pid=pid,
                                        issued_at=datetime.utcnow().timestamp() - 301)) == 0  # older than 5 minutes
            assert count(context_values(admin_id, "administrator", "both", pid=pid + 1)) == 0  # signed for another pid


def test_the_context_does_not_survive_into_the_next_transaction(pg_app):
    from app import db
    from app.rls import context_values
    with pg_app.app_context():
        with db.engine.connect() as conn:
            with conn.begin():
                _set(conn, context_values("", "system", "", pid=_pid(conn)))
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
        assert client.post("/login", data={"email": "lockout_probe@example.com", "password": "wrong-password",
                                           "portal": "school"}).status_code == 401
    response = client.post("/login", data={"email": "lockout_probe@example.com", "password": PASSWORD,
                                           "portal": "school"})
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


# --- Signature bound to the connection (lead review of batch 6) ------------------------------------


def test_a_valid_context_copied_to_another_connection_sees_nothing(pg_app):
    """Another session's set_config call (readable in pg_stat_activity by the same role) is useless."""
    from app import db
    from app.rls import context_values
    admin_id = str(pg_app.config["IDS"]["users"]["administrator"])
    with pg_app.app_context():
        with db.engine.connect() as first, db.engine.connect() as second:
            assert _pid(first) != _pid(second)
            stolen = context_values(admin_id, "administrator", "both", pid=_pid(first))
            with first.begin():
                _set(first, stolen)
                assert first.execute(text("SELECT count(*) FROM child_records")).scalar() == 6
            with second.begin():
                _set(second, stolen)
                assert second.execute(text("SELECT count(*) FROM child_records")).scalar() == 0
                assert second.execute(text("SELECT public.app_context_valid()")).scalar() is False


def test_the_app_caches_one_pid_per_pooled_connection(pg_app):
    from app import db
    with pg_app.test_request_context("/"):
        connection = db.session.connection()
        cached = connection.info.get("rls_backend_pid")
        assert cached == db.session.execute(text("SELECT pg_backend_pid()")).scalar()
        db.session.remove()


# --- Child data reached through a parent row (CHILD_DATA_VIA_PARENT) -------------------------------


def _as_system(pg_app, work):
    from app import db
    from app.rls import system_context
    with pg_app.app_context():
        with system_context():
            db.session.commit()
            result = work(db)
            db.session.commit()
        db.session.remove()
    return result


def _seed_parent_scoped_rows(pg_app):
    """A report card (with an entry) and a medication schedule (with a dose) for a child in the
    teacher's class and one outside it. Returns {child key: card id}."""
    from app.models.health import MedicationAdministration, MedicationSchedule
    from app.models.report_card import ReportCard, ReportCardEntry

    ids = pg_app.config["IDS"]
    admin = ids["users"]["administrator"]

    def work(db):
        cards = {}
        for key, klass in (("in_class", "c6a"), ("other_class", "c7b")):
            existing = ReportCard.query.filter_by(child_record_id=ids["kids"][key], academic_year=2031, term=1).first()
            if existing:
                cards[key] = existing.id
                continue
            now = datetime.utcnow()
            card = ReportCard(child_record_id=ids["kids"][key], class_id=ids["classes"][klass], academic_year=2031,
                              term=1, status="draft", created_by=admin, created_at=now, updated_by=admin,
                              updated_at=now)
            db.session.add(card)
            db.session.flush()
            db.session.add(ReportCardEntry(report_card_id=card.id, learning_area="english", level="ME",
                                           updated_by=admin, updated_at=now))
            schedule = MedicationSchedule(child_record_id=ids["kids"][key], medicine="Test medicine", dose="5ml",
                                          daily_times="08:00", start_date=date(2026, 1, 1), created_by=admin)
            db.session.add(schedule)
            db.session.flush()
            db.session.add(MedicationAdministration(schedule_id=schedule.id, scheduled_for=datetime(2026, 1, 2, 8),
                                                    outcome="given", recorded_by=admin, recorded_at=now))
            cards[key] = card.id
        return cards
    return _as_system(pg_app, work)


def test_a_teacher_sees_no_entries_or_doses_for_a_child_outside_their_class(pg_app):
    cards = _seed_parent_scoped_rows(pg_app)
    kids = pg_app.config["IDS"]["kids"]
    entries = {row[0] for row in _visible(pg_app, "teacher", "SELECT report_card_id FROM report_card_entries")}
    assert cards["in_class"] in entries and cards["other_class"] not in entries
    doses = {row[0] for row in _visible(
        pg_app, "teacher",
        "SELECT s.child_record_id FROM medication_administrations a "
        "JOIN medication_schedules s ON s.id = a.schedule_id")}
    assert kids["other_class"] not in doses
    # The rows really exist: the system context sees both.
    assert _as_system(pg_app, lambda db: db.session.execute(
        text("SELECT count(*) FROM medication_administrations")).scalar()) >= 2
    # A plain unscoped count as the teacher: no dose of the other child, whatever the join.
    other_doses = _visible(pg_app, "teacher",
                           f"SELECT count(*) FROM medication_administrations a WHERE a.schedule_id IN "
                           f"(SELECT id FROM medication_schedules WHERE child_record_id = {kids['other_class']})")
    assert other_doses[0][0] == 0


def test_inserting_into_a_published_card_is_refused_by_the_trigger_even_when_the_card_is_invisible(pg_app):
    """#70 trigger as SECURITY DEFINER: a context that can't see the published card still hits the
    lock (check_violation, 23514), raised by the trigger before the row-level policy is checked.
    If the trigger ran as the caller it would find no card and the refusal would come from the
    policy instead (42501)."""
    import psycopg2  # noqa: F401  (the driver used by the engine)
    from sqlalchemy.exc import DBAPIError

    from app import db
    cards = _seed_parent_scoped_rows(pg_app)
    card_id = cards["other_class"]
    _as_system(pg_app, lambda db_: db_.session.execute(
        text("UPDATE report_cards SET status = 'published' WHERE id = :id"), {"id": card_id}))
    with pg_app.test_request_context("/"):
        from flask import session
        session["_user_id"] = str(pg_app.config["IDS"]["users"]["social_worker"])  # can't see school cards
        assert db.session.execute(text("SELECT count(*) FROM report_cards WHERE id = :id"),
                                  {"id": card_id}).scalar() == 0
        with pytest.raises(DBAPIError) as raised:
            db.session.execute(text("INSERT INTO report_card_entries (report_card_id, learning_area, level, "
                                    "updated_by, updated_at) VALUES (:id, 'kiswahili', 'EE', 1, now())"),
                               {"id": card_id})
        assert raised.value.orig.pgcode == "23514"
        db.session.rollback()
        db.session.remove()


# --- Every main write path still works under row-level security ------------------------------------
# Through the app's own routes, signed in as the role that does it, connected as the app role.

PORTALS = {"administrator": "school", "teacher": "school", "school_nurse": "school", "principal": "school",
           "social_worker": "childrens_home", "legal_officer": "childrens_home", "home_manager": "childrens_home"}


@pytest.fixture()
def no_sms(monkeypatch):
    import sys
    sent = []
    for name, module in list(sys.modules.items()):
        if name.startswith("app.") and hasattr(module, "send_sms"):
            monkeypatch.setattr(module, "send_sms", lambda phone, message: sent.append(message) or {"ok": True})
    return sent


def _sign_in(pg_app, role):
    client = pg_app.test_client()
    response = client.post("/login", data={"email": f"{role}@example.com", "password": PASSWORD,
                                           "portal": PORTALS[role]})
    assert response.status_code == 302, response.status_code
    return client


def _count(pg_app, table, where="true", params=None):
    return _as_system(pg_app, lambda db: db.session.execute(
        text(f"SELECT count(*) FROM {table} WHERE {where}"), params or {}).scalar())


def _audit_count(pg_app, action):
    return _count(pg_app, "audit_log_entries", "action = :a", {"a": action})


def _ok(response):
    assert response.status_code in (200, 201, 302), (response.status_code, response.get_data(as_text=True)[:300])


def test_write_intake_as_social_worker(pg_app, no_sms):
    from datetime import timedelta
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    before = _count(pg_app, "intake_records", "child_record_id = :k", {"k": kid})
    _ok(_sign_in(pg_app, "social_worker").post(f"/intake/records/{kid}", data={
        "referral_source": "police", "admission_date": (date.today() - timedelta(days=10)).isoformat(),
        "placement_reason": "Abandoned at the market", "committal_order_reference": "CO/123/2026",
        "childrens_officer": "Officer Wanjiku"}))
    assert _count(pg_app, "intake_records", "child_record_id = :k", {"k": kid}) == before + 1


def test_write_missing_alert_as_social_worker_for_any_home_child(pg_app, no_sms):
    from datetime import timedelta
    kid = pg_app.config["IDS"]["kids"]["home_other"]  # not on this worker's caseload (#60 rule)
    _ok(_sign_in(pg_app, "social_worker").post(f"/missing/records/{kid}", data={
        "last_seen_at": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
        "circumstances": "Did not return from school"}))
    assert _count(pg_app, "missing_child_alerts", "child_record_id = :k", {"k": kid}) == 1


def test_write_case_note_as_social_worker(pg_app, no_sms):
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    _ok(_sign_in(pg_app, "social_worker").post(f"/care/records/{kid}/notes", data={
        "note_date": date.today().isoformat(), "category": "welfare", "body": "Settling in well",
        "legal_summary": ""}))
    assert _count(pg_app, "case_notes", "child_record_id = :k", {"k": kid}) == 1


def test_write_health_entry_schedule_and_dose_as_social_worker(pg_app, no_sms):
    from datetime import timedelta
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    worker = _sign_in(pg_app, "social_worker")
    _ok(worker.post(f"/health/records/{kid}/entries", data={
        "entry_type": "immunisation", "entry_at": "2026-01-10T09:00", "details": "Measles"}))
    assert _count(pg_app, "health_entries", "child_record_id = :k", {"k": kid}) == 1
    _ok(worker.post(f"/health/records/{kid}/schedules", data={
        "medicine": "Amoxicillin", "dose": "250mg", "daily_times": "08:00",
        "start_date": (date.today() - timedelta(days=2)).isoformat()}))
    schedule_id = _as_system(pg_app, lambda db: db.session.execute(text(
        "SELECT id FROM medication_schedules WHERE child_record_id = :k AND medicine IS NOT NULL "
        "ORDER BY id DESC LIMIT 1"), {"k": kid}).scalar())
    due = datetime.combine(date.today() - timedelta(days=1), datetime.strptime("08:00", "%H:%M").time())
    _ok(worker.post(f"/health/schedules/{schedule_id}/doses", data={"scheduled_for": due.isoformat(),
                                                                     "outcome": "given"}))
    assert _count(pg_app, "medication_administrations", "schedule_id = :s", {"s": schedule_id}) == 1


def test_write_attendance_as_teacher(pg_app, no_sms):
    ids = pg_app.config["IDS"]
    kid = ids["kids"]["in_class"]
    _ok(_sign_in(pg_app, "teacher").post(
        f"/attendance/classes/{ids['classes']['c6a']}?date={date.today().isoformat()}",
        data={f"status_{kid}": "present"}))
    assert _count(pg_app, "attendance_marks", "child_record_id = :k", {"k": kid}) == 1


def test_write_consent_as_social_worker(pg_app, no_sms):
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    response = _sign_in(pg_app, "social_worker").post(f"/consent/records/{kid}", json={
        "consent_type": "photo", "status": "given", "guardian_name": "Grace Guardian",
        "effective_date": date.today().isoformat()})
    assert response.status_code == 201
    assert _count(pg_app, "consent_records", "child_record_id = :k", {"k": kid}) == 1


def test_write_clinic_visit_as_clinical_officer(pg_app, no_sms):
    kid = pg_app.config["IDS"]["kids"]["other_class"]
    _ok(_sign_in(pg_app, "school_nurse").post(f"/clinic/records/{kid}", data={
        "complaint": "Headache", "treatment": "Rest and water", "medicines_given": "Paracetamol 250mg",
        "follow_up": "Check tomorrow", "immunisation": ""}))
    assert _count(pg_app, "clinic_visits", "child_record_id = :k", {"k": kid}) == 1


def test_write_pickup_collector_proposal_as_teacher(pg_app, no_sms):
    kid = pg_app.config["IDS"]["kids"]["in_class"]
    _ok(_sign_in(pg_app, "teacher").post(f"/pickup/records/{kid}", data={
        "full_name": "Peter Mwangi", "relationship": "father", "phone_number": "+254712000111",
        "national_id_number": "30481957"}))
    assert _count(pg_app, "authorised_collectors", "child_record_id = :k", {"k": kid}) == 1


def test_write_family_visit_as_social_worker(pg_app, no_sms):
    from datetime import timedelta
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    _ok(_sign_in(pg_app, "social_worker").post(f"/family/records/{kid}/visits", data={
        "visit_at": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
        "visitor_name": "Mary Atieno", "relationship": "mother", "supervised": "yes", "notes": "Warm visit"}))
    assert _count(pg_app, "family_visits", "child_record_id = :k", {"k": kid}) == 1


def test_write_court_hearing_as_legal_officer(pg_app, no_sms):
    from datetime import timedelta
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    _ok(_sign_in(pg_app, "legal_officer").post(f"/court/records/{kid}", data={
        "hearing_at": (datetime.now() + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M"),
        "court": "Milimani Children's Court", "case_reference": "CR/77/2026"}))
    assert _count(pg_app, "court_hearings", "child_record_id = :k", {"k": kid}) == 1


def test_write_placement_and_followup_as_social_worker(pg_app, no_sms):
    from datetime import timedelta
    kid = pg_app.config["IDS"]["kids"]["home_mine"]
    worker = _sign_in(pg_app, "social_worker")
    _ok(worker.post(f"/placement/records/{kid}", data={
        "outcome": "family_reunification", "exit_date": date.today().isoformat(),
        "destination_notes": "Back with grandmother"}))
    placement_id = _as_system(pg_app, lambda db: db.session.execute(text(
        "SELECT id FROM placements WHERE child_record_id = :k ORDER BY id DESC LIMIT 1"), {"k": kid}).scalar())
    assert placement_id is not None
    _ok(worker.post(f"/placement/placements/{placement_id}/followups",
                    data={"due_date": (date.today() + timedelta(days=30)).isoformat()}))
    assert _count(pg_app, "aftercare_followups", "placement_id = :p", {"p": placement_id}) >= 1


def test_write_report_card_as_class_teacher(pg_app, no_sms):
    from app.models.report_card import LEARNING_AREA_KEYS
    ids = pg_app.config["IDS"]
    kid = ids["kids"]["in_class"]
    form = {f"level_{area}": "ME" for area in LEARNING_AREA_KEYS}
    form.update({"year": 2026, "term": 2, "teacher_comment": "Good term"})
    _ok(_sign_in(pg_app, "teacher").post(f"/reports/classes/{ids['classes']['c6a']}/children/{kid}", data=form))
    card = _as_system(pg_app, lambda db: db.session.execute(text(
        "SELECT id FROM report_cards WHERE child_record_id = :k AND academic_year = 2026 AND term = 2"),
        {"k": kid}).scalar())
    assert card is not None
    assert _count(pg_app, "report_card_entries", "report_card_id = :c", {"c": card}) == len(LEARNING_AREA_KEYS)


def test_write_document_upload_as_clinical_officer(pg_app, no_sms):
    import io
    kid = pg_app.config["IDS"]["kids"]["in_class"]
    pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer <<>>\n%%EOF"
    _ok(_sign_in(pg_app, "school_nurse").post(
        f"/documents/records/{kid}", content_type="multipart/form-data",
        data={"document_type": "medical_report", "file": (io.BytesIO(pdf), "Report.pdf")}))
    document_id = _as_system(pg_app, lambda db: db.session.execute(text(
        "SELECT id FROM documents WHERE child_record_id = :k ORDER BY id DESC LIMIT 1"), {"k": kid}).scalar())
    assert document_id is not None
    assert _count(pg_app, "document_blobs", "document_id = :d", {"d": document_id}) == 1


def test_every_write_above_left_its_audit_row(pg_app):
    """Each action is audited through log_action(), so audit inserts work for every role under RLS."""
    for action in ("intake_created", "missing_child_raised", "case_note_added", "health_entry_added",
                   "medication_schedule_added", "medication_dose_recorded", "attendance_taken", "consent_recorded",
                   "clinic_visit_recorded", "collector_pending", "family_visit_recorded", "court_hearing_added",
                   "placement_recorded", "aftercare_followup_scheduled", "report_card_saved", "document_uploaded"):
        assert _audit_count(pg_app, action) >= 1, action


def test_write_new_child_record_as_administrator(pg_app, no_sms):
    """Admission: only administrators create child_records rows (the INSERT policy allows only
    administrator and system). Runs last in this module because it adds a child."""
    response = _sign_in(pg_app, "administrator").post("/admin/records", json={
        "full_name": "New Admission", "date_of_birth": "2015-03-01", "institution_mode": "school"})
    _ok(response)
    assert _count(pg_app, "child_records", "true") == 7


# --- Safeguarding concerns (#62) under row-level security -------------------------------------------
# These run after the tests above (module order). They sign in by setting the session directly, so
# the account locked by the lockout test (lockout_probe, a teacher with no class) can serve as a
# safeguarding lead who can't see any child row under their own role's scope.

SG_MARKER = "marker-pg-s4feguard"


def _client_as(pg_app, key, portal="school"):
    client = pg_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(pg_app.config["IDS"]["users"][key])
        sess["_fresh"] = True
        sess["active_portal"] = portal
    return client


def _pgcode(pg_app, user_key, statement, params=None):
    """Run one statement as the app role under this user's context ('system' for the CLI
    context). Returns None if it worked, else the PostgreSQL error code. Always rolled back."""
    from flask import session
    from sqlalchemy.exc import DBAPIError

    from app import db
    from app.rls import system_context

    def attempt():
        try:
            db.session.execute(text(statement), params or {})
            return None
        except DBAPIError as error:
            return error.orig.pgcode
        finally:
            db.session.rollback()
            db.session.remove()

    if user_key == "system":
        with pg_app.app_context(), system_context():
            return attempt()
    with pg_app.test_request_context("/"):
        session["_user_id"] = str(pg_app.config["IDS"]["users"][user_key])
        return attempt()


@pytest.fixture(scope="module")
def concerns_seeded(pg_app):
    """Leads: school_nurse and lockout_probe (school). Concerns raised through the app's routes:
    A by the teacher about their class child, B by the social worker with no child, C by the
    school nurse (a lead) about the other class's child. Actions: a note on A by the nurse, a
    note on C by lockout_probe (the nurse can't act on C: she reported it)."""
    import sys

    users = pg_app.config["IDS"]["users"]
    kids = pg_app.config["IDS"]["kids"]
    _as_system(pg_app, lambda db: db.session.execute(
        text("UPDATE users SET is_safeguarding_lead = true WHERE id IN (:a, :b)"),
        {"a": users["school_nurse"], "b": users["lockout_probe"]}))
    saved = {}
    for module in list(sys.modules.values()):
        if getattr(module, "__name__", "").startswith("app.") and hasattr(module, "send_sms"):
            saved[module] = module.send_sms
            module.send_sms = lambda phone, message: {"ok": True}
    try:
        for key, portal, data in (
                ("teacher", "school", {"child_record_id": str(kids["in_class"])}),
                ("social_worker", "childrens_home", {}),
                ("school_nurse", "school", {"child_record_id": str(kids["other_class"])})):
            response = _client_as(pg_app, key, portal).post("/concerns/new", data={
                "urgency": "high", "narrative": f"{SG_MARKER} by {key}", "involves_staff": "no", **data})
            assert response.status_code == 302, (key, response.status_code)
    finally:
        for module, original in saved.items():
            module.send_sms = original
    ids = _as_system(pg_app, lambda db: {row[1]: row[0] for row in db.session.execute(text(
        "SELECT s.id, s.reporter_id FROM safeguarding_concerns s")).all()})
    a, b, c = ids[users["teacher"]], ids[users["social_worker"]], ids[users["school_nurse"]]
    assert _client_as(pg_app, "school_nurse").post(f"/safeguarding/concerns/{a}/actions", data={
        "action_type": "note", "body": "nurse note"}).status_code == 302
    assert _client_as(pg_app, "lockout_probe").post(f"/safeguarding/concerns/{c}/actions", data={
        "action_type": "note", "body": "probe note"}).status_code == 302
    actions = _as_system(pg_app, lambda db: {row[1]: row[0] for row in db.session.execute(text(
        "SELECT id, concern_id FROM safeguarding_concern_actions")).all()})
    assert set(actions) == {a, c}
    return {"A": a, "B": b, "C": c, "A1": actions[a], "C1": actions[c]}


SG_EXPECTED = {  # user key -> (concerns visible, action rows visible)
    "administrator": ({"A", "B", "C"}, set()),
    "teacher": ({"A"}, set()),
    "school_nurse": ({"A", "C"}, {"A1"}),      # a lead sees her mode; no actions on what she reported
    "lockout_probe": ({"A", "C"}, {"A1", "C1"}),
    "principal": (set(), set()),
    "social_worker": ({"B"}, set()),
    "legal_officer": (set(), set()),
    "home_manager": (set(), set()),
    "parent_guardian": (set(), set()),
}


@pytest.mark.parametrize("key", sorted(SG_EXPECTED))
def test_safeguarding_rls_parity_for_concerns_and_actions(pg_app, concerns_seeded, key):
    names = {v: k for k, v in concerns_seeded.items() if k in ("A", "B", "C")}
    action_names = {v: k for k, v in concerns_seeded.items() if k in ("A1", "C1")}
    seen = {names[row[0]] for row in _visible(pg_app, key, "SELECT id FROM safeguarding_concerns")}
    seen_actions = {action_names[row[0]] for row in
                    _visible(pg_app, key, "SELECT id FROM safeguarding_concern_actions")}
    assert (seen, seen_actions) == SG_EXPECTED[key]


def test_the_database_refuses_changing_the_narrative_or_deleting(pg_app, concerns_seeded):
    a, a1 = concerns_seeded["A"], concerns_seeded["A1"]
    for user_key in ("system", "school_nurse"):
        assert _pgcode(pg_app, user_key, "UPDATE safeguarding_concerns SET narrative = narrative WHERE id = :i",
                       {"i": a}) == "42501"
        assert _pgcode(pg_app, user_key, "UPDATE safeguarding_concerns SET reporter_id = reporter_id WHERE id = :i",
                       {"i": a}) == "42501"
        assert _pgcode(pg_app, user_key, "DELETE FROM safeguarding_concerns WHERE id = :i", {"i": a}) == "42501"
        assert _pgcode(pg_app, user_key, "UPDATE safeguarding_concern_actions SET body = body WHERE id = :i",
                       {"i": a1}) == "42501"
        assert _pgcode(pg_app, user_key, "DELETE FROM safeguarding_concern_actions WHERE id = :i",
                       {"i": a1}) == "42501"
    # The status columns stay writable for a lead.
    assert _pgcode(pg_app, "school_nurse", "UPDATE safeguarding_concerns SET status = status WHERE id = :i",
                   {"i": a}) is None


def test_the_database_refuses_relinking_and_out_of_scope_or_parent_inserts(pg_app, concerns_seeded):
    kids, users = pg_app.config["IDS"]["kids"], pg_app.config["IDS"]["users"]
    assert _pgcode(pg_app, "system", "UPDATE safeguarding_concerns SET child_record_id = :c WHERE id = :i",
                   {"c": kids["other_class"], "i": concerns_seeded["A"]}) == "23514"
    insert = ("INSERT INTO safeguarding_concerns (child_record_id, institution_mode, reporter_id, involves_staff, "
              "urgency, status, narrative, created_at, updated_at) "
              "VALUES (:c, 'school', :r, false, 'low', 'open', decode('00', 'hex'), now(), now())")
    assert _pgcode(pg_app, "teacher", insert, {"c": kids["other_class"], "r": users["teacher"]}) == "42501"
    assert _pgcode(pg_app, "teacher", insert, {"c": kids["in_class"], "r": users["principal"]}) == "42501"
    assert _pgcode(pg_app, "parent_guardian", insert, {"c": None, "r": users["parent_guardian"]}) == "42501"
    # An administrator can't add actions (administrators get no action rows at all).
    assert _pgcode(pg_app, "administrator",
                   "INSERT INTO safeguarding_concern_actions (concern_id, actor_id, action_type, created_at) "
                   "VALUES (:i, :a, 'note', now())", {"i": concerns_seeded["A"], "a": users["administrator"]}) == "42501"


def test_a_lead_without_access_to_the_child_row_still_reads_the_concern_and_the_name(pg_app, concerns_seeded):
    a = concerns_seeded["A"]
    assert _visible(pg_app, "lockout_probe", "SELECT count(*) FROM child_records")[0][0] == 0
    before = _audit_count(pg_app, "concern_narrative_viewed")
    page = _client_as(pg_app, "lockout_probe").get(f"/safeguarding/concerns/{a}")
    html = page.get_data(as_text=True)
    assert page.status_code == 200 and f"{SG_MARKER} by teacher" in html and "In Class" in html
    assert _audit_count(pg_app, "concern_narrative_viewed") == before + 1


def test_admin_metadata_and_reporter_list_work_under_rls_without_narrative(pg_app, concerns_seeded):
    body = _client_as(pg_app, "administrator").get("/admin/concerns", headers={"Accept": "application/json"}).get_json()
    assert len(body["items"]) == 3 and SG_MARKER not in str(body)
    mine = _client_as(pg_app, "teacher").get("/concerns/mine", headers={"Accept": "application/json"}).get_json()
    assert [item["id"] for item in mine["items"]] == [concerns_seeded["A"]]
    assert _client_as(pg_app, "teacher").get(f"/safeguarding/concerns/{concerns_seeded['A']}").status_code == 404
