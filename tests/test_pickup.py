"""Authorised pickup list (#51) and pending collectors (#112)."""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.pickup import AuthorisedCollector
from app.models.user import Role, User
from app.services.pickup_service import GUARDIAN_NOTICE
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "teacher2": "school", "principal": "school",
         "school_nurse": "school", "social_worker": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}
COLLECTOR = {"full_name": "Peter Mwangi (marker-p1ck)", "relationship": "father", "phone_number": "+254712000111",
             "national_id_number": "30481957"}


@pytest.fixture(autouse=True)
def sms(monkeypatch):
    sent = []
    monkeypatch.setattr("app.services.sms_service.send_sms", lambda phone, message: sent.append((phone, message)))
    return sent


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for key, mode in ROLES.items():
            role_name = "teacher" if key.startswith("teacher") else key
            role = Role.query.filter_by(name=role_name).first() or Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        mine = ChildRecord(full_name="Amina Achieng", date_of_birth=date(2014, 1, 1), institution_mode="school",
                           guardian_contact="+254711000222")
        other = ChildRecord(full_name="Other Class", date_of_birth=date(2014, 1, 1), institution_mode="school")
        home = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           caseload_worker_id=users["social_worker"].id)
        deleted = ChildRecord(full_name="Deleted", date_of_birth=date(2014, 1, 1), institution_mode="school",
                              is_deleted=True)
        db.session.add_all([mine, other, home, deleted])
        db.session.flush()
        put_in_class("Grade 6A", children=[mine, deleted], teachers=[users["teacher"]])
        put_in_class("Grade 7C", children=[other], teachers=[users["teacher2"]])
        db.session.commit()
        application.config.update(MINE=mine.id, OTHER=other.id, HOME=home.id, DELETED=deleted.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    role = "teacher" if key.startswith("teacher") else key
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key] if key in ROLES else ROLES[role]]}).status_code == 302
    return client


def add(app, client, record_key="MINE", **overrides):
    return client.post(f"/pickup/records/{app.config[record_key]}", data={**COLLECTOR, **overrides})


def collectors(app, active=None):
    with app.app_context():
        query = AuthorisedCollector.query
        if active is not None:
            query = query.filter_by(is_active=active)
        return query.count()


# --- Who manages and who reads -------------------------------------------------------------------


def test_teacher_adds_and_revokes_for_their_own_class(app):
    teacher = sign_in(app, "teacher")
    assert add(app, teacher).status_code == 302
    assert collectors(app, active=True) == 1
    with app.app_context():
        collector_id = AuthorisedCollector.query.one().id
    teacher.post(f"/pickup/collectors/{collector_id}/revoke")
    assert collectors(app, active=False) == 1 and collectors(app) == 1  # revoked, never deleted


def test_admin_manages_any_school_record(app):
    assert add(app, sign_in(app, "administrator"), "OTHER").status_code == 302
    assert collectors(app) == 1


@pytest.mark.parametrize("key, record_key", [("teacher", "OTHER"), ("teacher2", "MINE"), ("school_nurse", "MINE"),
                                             ("social_worker", "HOME"), ("administrator", "HOME"),
                                             ("administrator", "DELETED")])
def test_out_of_scope_requests_answer_404(app, key, record_key):
    client = sign_in(app, key)
    assert client.get(f"/pickup/records/{app.config[record_key]}").status_code == 404
    assert add(app, client, record_key).status_code == 404
    assert collectors(app) == 0


def test_principal_reads_but_cannot_change(app):
    add(app, sign_in(app, "teacher"))
    principal = sign_in(app, "principal")
    html = principal.get(f"/pickup/records/{app.config['MINE']}").get_data(as_text=True)
    assert "Peter Mwangi" in html and 'name="full_name"' not in html
    assert add(app, principal, full_name="Someone Else").status_code == 403
    with app.app_context():
        collector_id = AuthorisedCollector.query.one().id
    assert principal.post(f"/pickup/collectors/{collector_id}/revoke").status_code == 403
    assert collectors(app, active=True) == 1


def test_revoking_through_another_class_is_refused(app):
    add(app, sign_in(app, "teacher"))
    with app.app_context():
        collector_id = AuthorisedCollector.query.one().id
    assert sign_in(app, "teacher2").post(f"/pickup/collectors/{collector_id}/revoke").status_code == 404
    assert collectors(app, active=True) == 1


# --- What each view shows -----------------------------------------------------------------------------


def test_full_id_number_is_for_administrators_only(app):
    add(app, sign_in(app, "teacher"))
    teacher_html = sign_in(app, "teacher").get(f"/pickup/records/{app.config['MINE']}").get_data(as_text=True)
    admin_html = sign_in(app, "administrator").get(f"/pickup/records/{app.config['MINE']}").get_data(as_text=True)
    assert "30481957" not in teacher_html and "…957" in teacher_html
    assert "30481957" in admin_html


def test_gate_check_shows_only_what_the_gate_needs(app):
    add(app, sign_in(app, "administrator"))
    html = sign_in(app, "teacher").get(f"/pickup/records/{app.config['MINE']}/check").get_data(as_text=True)
    assert "Peter Mwangi" in html and "father" in html and "…957" in html
    assert "+254712000111" not in html and "30481957" not in html


def test_revoked_collectors_disappear_from_the_gate_check(app):
    teacher = sign_in(app, "teacher")
    add(app, sign_in(app, "administrator"))
    with app.app_context():
        collector_id = AuthorisedCollector.query.one().id
    teacher.post(f"/pickup/collectors/{collector_id}/revoke")
    html = teacher.get(f"/pickup/records/{app.config['MINE']}/check").get_data(as_text=True)
    assert "Peter Mwangi" not in html and "No one is authorised" in html


# --- Validation, encryption, audit -----------------------------------------------------------------


@pytest.mark.parametrize("bad", [{"full_name": ""}, {"relationship": "neighbour"}, {"phone_number": "0712000111"},
                                 {"national_id_number": "12"}, {"national_id_number": "1234-5678"}])
def test_invalid_input_is_refused(app, bad):
    add(app, sign_in(app, "teacher"), **bad)
    assert collectors(app) == 0


def test_collector_details_are_ciphertext_at_rest(app):
    add(app, sign_in(app, "teacher"))
    with app.app_context():
        row = db.session.execute(text("SELECT full_name, phone_number, national_id_number FROM authorised_collectors")).one()
    stored = b"".join(bytes(value) for value in row)
    for plain in (b"Mwangi", b"+254712000111", b"30481957"):
        assert plain not in stored


def test_audit_rows_carry_no_names_phones_or_id_numbers(app):
    teacher = sign_in(app, "teacher")
    add(app, teacher)
    teacher.get(f"/pickup/records/{app.config['MINE']}/check")
    with app.app_context():
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
        assert AuditLogEntry.query.filter_by(action="collector_pending").count() == 1  # a teacher proposed it (#112)
        assert AuditLogEntry.query.filter_by(action="pickup_check_viewed").count() == 1
    for secret in ("Mwangi", "+254712000111", "30481957"):
        assert secret not in details


def test_collector_table_allows_updates_to_revoke_columns_only():
    from app.db_roles import COLUMN_UPDATE_TABLES

    assert {"is_active", "revoked_by", "revoked_at"} <= set(COLUMN_UPDATE_TABLES["authorised_collectors"])


# --- #112: teacher additions wait for an administrator ------------------------------------------------


def only_collector(app):
    with app.app_context():
        return AuthorisedCollector.query.one()


def gate_html(app, client):
    return client.get(f"/pickup/records/{app.config['MINE']}/check").get_data(as_text=True)


def audit_actions(app):
    with app.app_context():
        return [row.action for row in AuditLogEntry.query.order_by(AuditLogEntry.id)]


def test_teacher_addition_is_invisible_at_the_gate_until_confirmed(app):
    teacher = sign_in(app, "teacher")
    add(app, teacher)
    assert only_collector(app).status == "pending"
    assert "Peter Mwangi" not in gate_html(app, teacher)
    assert "collector_pending" in audit_actions(app)

    sign_in(app, "administrator").post(f"/pickup/collectors/{only_collector(app).id}/confirm")

    assert only_collector(app).status == "active"
    assert "Peter Mwangi" in gate_html(app, teacher)
    assert "collector_confirmed" in audit_actions(app)


def test_administrator_addition_is_active_immediately(app):
    admin = sign_in(app, "administrator")
    add(app, admin)
    assert only_collector(app).status == "active"
    assert "Peter Mwangi" in gate_html(app, admin)
    assert "collector_added" in audit_actions(app) and "collector_pending" not in audit_actions(app)


def test_rejected_collectors_never_reach_the_gate(app):
    teacher = sign_in(app, "teacher")
    add(app, teacher)
    sign_in(app, "administrator").post(f"/pickup/collectors/{only_collector(app).id}/reject")
    collector = only_collector(app)
    assert (collector.status, collector.is_active) == ("rejected", False)
    assert "Peter Mwangi" not in gate_html(app, teacher)
    assert "collector_rejected" in audit_actions(app)


@pytest.mark.parametrize("decision", ["confirm", "reject"])
def test_a_teacher_cannot_confirm_or_reject_their_own_addition(app, decision):
    teacher = sign_in(app, "teacher")
    add(app, teacher)
    response = teacher.post(f"/pickup/collectors/{only_collector(app).id}/{decision}")
    assert response.status_code == 403
    assert only_collector(app).status == "pending"


def test_principal_cannot_confirm(app):
    add(app, sign_in(app, "teacher"))
    assert sign_in(app, "principal").post(f"/pickup/collectors/{only_collector(app).id}/confirm").status_code == 403
    assert only_collector(app).status == "pending"


def test_confirming_twice_or_a_revoked_collector_is_refused(app):
    admin = sign_in(app, "administrator")
    add(app, sign_in(app, "teacher"))
    collector_id = only_collector(app).id
    admin.post(f"/pickup/collectors/{collector_id}/confirm")
    admin.post(f"/pickup/collectors/{collector_id}/reject")  # no longer pending: refused
    assert only_collector(app).status == "active"
    admin.post(f"/pickup/collectors/{collector_id}/revoke")
    admin.post(f"/pickup/collectors/{collector_id}/confirm")
    assert only_collector(app).status == "revoked"


@pytest.mark.parametrize("adder", ["teacher", "administrator"])
def test_every_addition_sends_the_guardian_a_generic_notice(app, sms, adder):
    add(app, sign_in(app, adder))
    assert sms == [("+254711000222", GUARDIAN_NOTICE)]
    assert "pickup_guardian_notice_sent" in audit_actions(app)


def test_guardian_notice_names_nobody():
    for word in ("Peter", "Mwangi", "Amina", "father"):
        assert word not in GUARDIAN_NOTICE
    assert GUARDIAN_NOTICE == ("A change was made to your child's authorised pickup list. "
                               "Contact the school if you did not request it.")


def test_sms_failure_never_blocks_the_addition(app, monkeypatch):
    def broken(phone, message):
        raise RuntimeError("provider down")

    monkeypatch.setattr("app.services.sms_service.send_sms", broken)
    add(app, sign_in(app, "teacher"))
    assert only_collector(app).status == "pending"
    assert "pickup_guardian_notice_failed" in audit_actions(app)


def test_no_guardian_contact_is_recorded(app, sms):
    add(app, sign_in(app, "administrator"), "OTHER")
    assert sms == []
    assert "pickup_guardian_notice_no_contact" in audit_actions(app)


def test_decision_columns_are_in_the_column_update_allowlist():
    from app.db_roles import COLUMN_UPDATE_TABLES

    assert {"status", "decided_by", "decided_at"} <= set(COLUMN_UPDATE_TABLES["authorised_collectors"])
    assert "full_name" not in COLUMN_UPDATE_TABLES["authorised_collectors"]
