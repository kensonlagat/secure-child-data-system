"""Audit log viewer (#31): administrators only, read-only, filtered and paginated, viewing is
audited (bounded), identifiers stay as keyed hashes, nothing is decrypted, output is escaped."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.user import Role, User
from app.services.key_derivation import keyed_hash

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
         "social_worker": "childrens_home", "legal_officer": "childrens_home", "home_manager": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}
CHILD_NAME = "Zawadi Testchild"
LEGACY_RAW = "MyPassw0rd!typed-in-email-box"


def entry(**values):
    values.setdefault("timestamp", datetime.utcnow())
    row = AuditLogEntry(**values)
    db.session.add(row)
    return row


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for key, mode in ROLES.items():
            role = Role(name=key, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=f"Staff {key}", phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        child = ChildRecord(full_name=CHILD_NAME, date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add(child)
        db.session.flush()
        old = datetime.utcnow() - timedelta(days=10)
        entry(user_id=users["teacher"].id, action="view_records", target_record_type="child_record",
              target_record_id=child.id, details="Viewed one record", timestamp=old)
        entry(user_id=users["teacher"].id, action="update_record", target_record_type="child_record",
              target_record_id=child.id, details="<script>alert(1)</script> updated guardian_contact")
        entry(attempted_identifier=f"unknown:{'a' * 40}", action="login_failed", details="Unknown account")
        entry(attempted_identifier=LEGACY_RAW, action="login_failed", details="Legacy row")
        entry(user_id=users["school_nurse"].id, attempted_identifier="school_nurse@example.com",
              action="login_success", details="Signed in")
        entry(user_id=users["teacher"].id, action="view_records", details="Synthetic row", is_synthetic=True)
        db.session.commit()
        application.config.update(CHILD=child.id, TEACHER=users["teacher"].id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def page(client, **params):
    return client.get("/audit/log", query_string=params)


def count(action):
    return AuditLogEntry.query.filter_by(action=action).count()


# --- Who can see it -------------------------------------------------------------------------------


def test_signed_out_visitor_cannot_open_the_audit_log(app):
    response = app.test_client().get("/audit/log")
    assert response.status_code in (302, 401)
    assert b"login_failed" not in response.data


@pytest.mark.parametrize("key", [k for k in ROLES if k != "administrator"])
def test_every_other_role_is_refused_and_the_refusal_is_audited(app, key):
    client = sign_in(app, key)
    response = page(client)
    assert response.status_code == 403
    assert b"Unknown account" not in response.data
    with app.app_context():
        assert AuditLogEntry.query.filter(AuditLogEntry.action == "access_denied",
                                          AuditLogEntry.details.like("%audit.view_log%")).count() == 1


def test_administrator_sees_entries_newest_first(app):
    response = page(sign_in(app, "administrator"))
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_data(as_text=True)
    assert body.index("update_record") < body.index("Viewed one record")


# --- Read-only ------------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_no_write_method_exists(app, method):
    client = sign_in(app, "administrator")
    with app.app_context():
        before = AuditLogEntry.query.count()
    response = getattr(client, method)("/audit/log", data={"id": 1})
    assert response.status_code == 405
    with app.app_context():
        assert AuditLogEntry.query.count() == before


def test_the_blueprint_has_only_get_routes(app):
    for rule in app.url_map.iter_rules():
        if rule.endpoint.startswith("audit."):
            assert rule.methods - {"HEAD", "OPTIONS"} == {"GET"}


# --- Nothing sensitive shown ----------------------------------------------------------------------


def test_unknown_identifiers_stay_hashed_and_legacy_raw_values_are_hashed_on_display(app):
    body = page(sign_in(app, "administrator")).get_data(as_text=True)
    assert f"unknown:{'a' * 40}" in body
    assert LEGACY_RAW not in body
    with app.app_context():
        assert f"unknown:{keyed_hash('audit-identifier', LEGACY_RAW)[:40]}" in body


def test_a_known_accounts_email_is_not_repeated_as_an_identifier(app):
    body = page(sign_in(app, "administrator")).get_data(as_text=True)
    assert "school_nurse@example.com" not in body
    assert "Staff school_nurse" in body


def test_the_page_never_decrypts_child_data(app):
    body = page(sign_in(app, "administrator")).get_data(as_text=True)
    assert CHILD_NAME not in body
    assert f"child_record #{app.config['CHILD']}" in body


def test_details_are_escaped(app):
    body = page(sign_in(app, "administrator")).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


# --- Viewing is audited, bounded -----------------------------------------------------------------


def test_viewing_is_audited_once_per_window_however_often_it_reloads(app):
    client = sign_in(app, "administrator")
    for _ in range(5):
        assert page(client).status_code == 200
        assert page(client, page=2).status_code == 200
    with app.app_context():
        assert count("audit_log_viewed") == 1


def test_view_audit_names_the_filters_but_not_their_values(app):
    client = sign_in(app, "administrator")
    assert page(client, action="update_record", target_record_id=app.config["CHILD"]).status_code == 200
    with app.app_context():
        row = AuditLogEntry.query.filter_by(action="audit_log_viewed").one()
        assert row.details == "Viewed audit log (filters: action, target_record_id)"
        assert row.target_record_type == "audit_log"


def test_view_audit_rows_are_capped_per_window(app):
    # Details name filters, not values, so each distinct row needs a distinct combination.
    from itertools import combinations
    values = {"user_id": app.config["TEACHER"], "action": "login_failed", "target_record_type": "child_record",
              "target_record_id": 1, "date_from": "2026-01-01", "date_to": "2027-01-01", "synthetic": "include"}
    combos = [dict((name, values[name]) for name in combo)
              for size in (1, 2, 3) for combo in combinations(values, size)]
    assert len(combos) > 20
    client = sign_in(app, "administrator")
    for params in combos:
        assert page(client, **params).status_code == 200
    with app.app_context():
        assert count("audit_log_viewed") == 20


# --- Filters --------------------------------------------------------------------------------------


def rows_in(response):
    return response.get_data(as_text=True).count('<span class="badge mono">')


def test_filters_by_user_action_record_and_date(app):
    client = sign_in(app, "administrator")
    teacher, child = app.config["TEACHER"], app.config["CHILD"]
    assert rows_in(page(client, user_id=teacher)) == 2
    assert rows_in(page(client, action="login_failed")) == 2
    assert rows_in(page(client, target_record_type="child_record", target_record_id=child)) == 2
    today = date.today().isoformat()
    assert rows_in(page(client, user_id=teacher, date_from=today)) == 1
    old = (date.today() - timedelta(days=10)).isoformat()
    assert rows_in(page(client, user_id=teacher, date_to=old)) == 1


def test_synthetic_rows_are_hidden_unless_asked_for(app):
    client = sign_in(app, "administrator")
    teacher = app.config["TEACHER"]
    assert "Synthetic row" not in page(client, user_id=teacher).get_data(as_text=True)
    assert rows_in(page(client, user_id=teacher, synthetic="include")) == 3
    assert rows_in(page(client, synthetic="only")) == 1


@pytest.mark.parametrize("params", [
    {"action": "login_failed' OR '1'='1"},
    {"action": "not_a_real_action"},
    {"target_record_type": "users; DROP TABLE"},
    {"user_id": "abc"},
    {"user_id": "999999"},
    {"target_record_id": "-1"},
    {"date_from": "yesterday"},
    {"date_from": "2026-02-30"},
    {"date_from": "2026-05-02", "date_to": "2026-05-01"},
    {"synthetic": "all"},
])
def test_bad_filters_are_refused_and_audited(app, params):
    client = sign_in(app, "administrator")
    response = page(client, **params)
    assert response.status_code == 400
    assert b"Unknown account" not in response.data
    with app.app_context():
        assert count("audit_log_filter_refused") == 1
        assert count("audit_log_viewed") == 0
        row = AuditLogEntry.query.filter_by(action="audit_log_filter_refused").one()
        for value in params.values():
            assert value not in (row.details or "")


# --- Pagination -----------------------------------------------------------------------------------


def test_pagination_splits_results_and_ignores_bad_paging_values(app):
    with app.app_context():
        for number in range(60):
            entry(user_id=app.config["TEACHER"], action="bulk_test_row", details=f"row {number}")
        db.session.commit()
    client = sign_in(app, "administrator")
    assert rows_in(page(client, action="bulk_test_row", per_page=25)) == 25
    last = page(client, action="bulk_test_row", per_page=25, page=3)
    assert rows_in(last) == 10
    assert "Page 3 of 3" in last.get_data(as_text=True)
    assert rows_in(page(client, action="bulk_test_row", per_page=100000)) == 50
    assert page(client, action="bulk_test_row", page="x").status_code == 200
    assert rows_in(page(client, action="bulk_test_row", page=99)) == 0
