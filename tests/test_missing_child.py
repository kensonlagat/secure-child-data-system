"""Missing child alerts (#60)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.missing import MissingChildAlert
from app.models.user import Role, User
from app.services.missing_service import MANAGER_SMS

PASSWORD = "Password#2026"
ROLES = {"social_worker": "childrens_home", "legal_officer": "childrens_home", "home_manager": "childrens_home",
         "administrator": "both", "teacher": "school"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}


@pytest.fixture()
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
        for index, (key, mode) in enumerate(ROLES.items(), start=1):
            role = Role(name=key, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number=f"+25470000000{index}",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        # A child outside the social worker's own caseload: any home staff can still raise.
        child = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home")
        school = ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([child, school])
        db.session.commit()
        application.config.update(CHILD=child.id, SCHOOL=school.id, MANAGER_PHONE=users["home_manager"].phone_number)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def raise_alert(app, client, key="CHILD", **extra):
    return client.post(f"/missing/records/{app.config[key]}", data={
        "last_seen_at": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
        "circumstances": "Did not return from school (marker-m1ss)", **extra})


def only_alert(app):
    with app.app_context():
        alert = MissingChildAlert.query.one()
        db.session.expunge(alert)
        return alert


@pytest.mark.parametrize("key", ["social_worker", "legal_officer", "home_manager", "administrator"])
def test_any_home_staff_can_raise(app, sms, key):
    assert raise_alert(app, sign_in(app, key)).status_code == 302
    assert only_alert(app).status == "open"


def test_manager_gets_an_immediate_sms_with_no_child_details(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    assert sms == [(app.config["MANAGER_PHONE"], MANAGER_SMS)]
    assert "Home Child" not in MANAGER_SMS and "school" not in MANAGER_SMS.lower()


def test_open_alert_is_prominent_for_the_manager_until_resolved(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    manager = sign_in(app, "home_manager")
    assert "1 open missing child" in manager.get("/home-mode/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert "1 open" in manager.get("/missing/").get_data(as_text=True)

    manager.post(f"/missing/alerts/{only_alert(app).id}/resolve",
                 data={"found_at": (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M"),
                       "resolution_notes": "Found at a friend's house (marker-f0und)"})

    assert only_alert(app).status == "resolved"
    assert "open missing child" not in manager.get("/home-mode/records", headers={"Accept": "text/html"}).get_data(as_text=True)


def test_banner_is_not_shown_to_other_staff(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    html = sign_in(app, "legal_officer").get("/home-mode/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert "open missing child" not in html


def test_raising_and_resolving_are_audited_with_timestamps(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    sign_in(app, "home_manager").post(f"/missing/alerts/{only_alert(app).id}/resolve",
                                      data={"found_at": datetime.now().strftime("%Y-%m-%dT%H:%M"),
                                            "resolution_notes": "Returned"})
    with app.app_context():
        raised = AuditLogEntry.query.filter_by(action="missing_child_raised").one()
        resolved = AuditLogEntry.query.filter_by(action="missing_child_resolved").one()
    assert "last seen" in raised.details and raised.timestamp is not None
    assert "found" in resolved.details and resolved.timestamp >= raised.timestamp


def test_only_manager_and_admin_resolve(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    response = sign_in(app, "social_worker").post(f"/missing/alerts/{only_alert(app).id}/resolve",
                                                  data={"found_at": datetime.now().strftime("%Y-%m-%dT%H:%M"),
                                                        "resolution_notes": "x"})
    assert response.status_code == 403 and only_alert(app).status == "open"


def test_one_open_alert_per_child(app, sms):
    worker = sign_in(app, "social_worker")
    raise_alert(app, worker)
    raise_alert(app, worker)
    with app.app_context():
        assert MissingChildAlert.query.count() == 1


@pytest.mark.parametrize("key, record_key", [("teacher", "CHILD"), ("social_worker", "SCHOOL")])
def test_non_home_staff_and_school_records_get_404(app, sms, key, record_key):
    assert raise_alert(app, sign_in(app, key), record_key).status_code == 404


def test_resolution_cannot_predate_last_seen(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    sign_in(app, "home_manager").post(f"/missing/alerts/{only_alert(app).id}/resolve",
                                      data={"found_at": (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M"),
                                            "resolution_notes": "x"})
    assert only_alert(app).status == "open"


def test_sms_failure_never_blocks_raising(app, monkeypatch):
    def broken(phone, message):
        raise RuntimeError("provider down")

    monkeypatch.setattr("app.services.sms_service.send_sms", broken)
    raise_alert(app, sign_in(app, "social_worker"))
    assert only_alert(app).status == "open"
    with app.app_context():
        assert "failed 1" in AuditLogEntry.query.filter_by(action="missing_child_manager_alerted").one().details


def test_text_is_ciphertext_and_never_audited(app, sms):
    raise_alert(app, sign_in(app, "social_worker"))
    with app.app_context():
        stored = bytes(db.session.execute(text("SELECT circumstances FROM missing_child_alerts")).scalar())
        details = " ".join(r.details or "" for r in AuditLogEntry.query.all())
    assert b"marker-m1ss" not in stored and "marker-m1ss" not in details
