"""Missing alert details are restricted (#122): only the raiser, the home manager and
administrators read circumstances, actions and resolution notes or update the actions. Other
home staff see the child's name and the time last seen. The same applies after resolution."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.missing import MissingChildAlert
from app.models.user import Role, User

PASSWORD = "Password#2026"
USERS = {"raiser": "social_worker", "other_worker": "social_worker", "legal_officer": "legal_officer",
         "home_manager": "home_manager", "administrator": "administrator"}
MODES = {"social_worker": "childrens_home", "legal_officer": "childrens_home", "home_manager": "childrens_home",
         "administrator": "both"}
SECRETS = ("marker-c1rc", "marker-act10n", "marker-r3s0lv")


@pytest.fixture(autouse=True)
def no_sms(monkeypatch):
    monkeypatch.setattr("app.services.sms_service.send_sms", lambda phone, message: None)


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        roles = {}
        for role_name, mode in MODES.items():
            roles[role_name] = Role(name=role_name, institution_mode=mode)
            db.session.add(roles[role_name])
        db.session.flush()
        for key, role_name in USERS.items():
            db.session.add(User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                                password_hash=generate_password_hash(PASSWORD), role_id=roles[role_name].id,
                                is_active=True))
        child = ChildRecord(full_name="Amani Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home")
        db.session.add(child)
        db.session.commit()
        application.config["CHILD"] = child.id
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    portal = "childrens_home"
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": portal}).status_code == 302
    return client


def raise_and_maybe_resolve(app, resolve):
    raiser = sign_in(app, "raiser")
    raiser.post(f"/missing/records/{app.config['CHILD']}", data={
        "last_seen_at": (datetime.now() - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M"),
        "circumstances": "Left after lunch (marker-c1rc)", "actions_taken": "Searched grounds (marker-act10n)"})
    if resolve:
        with app.app_context():
            alert_id = MissingChildAlert.query.one().id
        sign_in(app, "home_manager").post(f"/missing/alerts/{alert_id}/resolve", data={
            "found_at": (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "resolution_notes": "Found at the market (marker-r3s0lv)"})


def views(app, key):
    client = sign_in(app, key)
    html = client.get(f"/missing/records/{app.config['CHILD']}").get_data(as_text=True)
    data = client.get(f"/missing/records/{app.config['CHILD']}", headers={"Accept": "application/json"}).get_json()
    return client, html, data


def alert_id(app):
    with app.app_context():
        return MissingChildAlert.query.one().id


@pytest.mark.parametrize("resolve", [False, True])
@pytest.mark.parametrize("key", ["other_worker", "legal_officer"])
def test_other_staff_see_only_name_and_last_seen(app, key, resolve):
    raise_and_maybe_resolve(app, resolve)
    _, html, data = views(app, key)

    assert "Amani Child" in html and "Last seen" in html
    assert data["child_name"] == "Amani Child" and data["alert"]["last_seen_at"]
    for secret in SECRETS:
        assert secret not in html and secret not in str(data)
    assert set(data["alert"]) == {"status", "last_seen_at"}


@pytest.mark.parametrize("resolve", [False, True])
@pytest.mark.parametrize("key", ["raiser", "home_manager", "administrator"])
def test_raiser_manager_and_admin_see_the_details(app, key, resolve):
    raise_and_maybe_resolve(app, resolve)
    _, html, data = views(app, key)
    assert "marker-c1rc" in html and data["alert"]["circumstances"] == "Left after lunch (marker-c1rc)"
    if resolve:
        assert "marker-r3s0lv" in html and data["alert"]["resolution_notes"]


def test_other_staff_cannot_update_actions_and_it_is_audited(app):
    raise_and_maybe_resolve(app, False)
    response = sign_in(app, "other_worker").post(f"/missing/alerts/{alert_id(app)}/actions",
                                                 data={"actions_taken": "Overwritten"})
    assert response.status_code == 403
    with app.app_context():
        assert MissingChildAlert.query.one().actions_taken == "Searched grounds (marker-act10n)"
        assert AuditLogEntry.query.filter_by(action="access_denied").count() >= 1


@pytest.mark.parametrize("key", ["raiser", "home_manager", "administrator"])
def test_raiser_manager_and_admin_can_update_actions(app, key):
    raise_and_maybe_resolve(app, False)
    response = sign_in(app, key).post(f"/missing/alerts/{alert_id(app)}/actions",
                                      data={"actions_taken": f"Police informed by {key}"})
    assert response.status_code == 302
    with app.app_context():
        assert MissingChildAlert.query.one().actions_taken == f"Police informed by {key}"


def test_after_resolution_other_staff_still_cannot_update(app):
    raise_and_maybe_resolve(app, True)
    response = sign_in(app, "other_worker").post(f"/missing/alerts/{alert_id(app)}/actions",
                                                 data={"actions_taken": "x"})
    assert response.status_code == 403


def test_summary_views_are_audited_as_summaries(app):
    raise_and_maybe_resolve(app, False)
    views(app, "other_worker")
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="missing_child_viewed",
                                             details="Viewed missing alert summary").count() == 2
