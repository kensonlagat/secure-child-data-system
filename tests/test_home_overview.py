"""Home manager overview (#61)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.care_plan import CarePlanGoal
from app.models.child_record import ChildRecord
from app.models.court import CourtHearing
from app.models.missing import MissingChildAlert
from app.models.placement import AftercareFollowUp, Placement
from app.models.user import Role, User

PASSWORD = "Password#2026"
ROLES = {"home_manager": "childrens_home", "administrator": "both", "social_worker": "childrens_home",
         "legal_officer": "childrens_home", "principal": "school"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}


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
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        a = ChildRecord(full_name="Secret Child A", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                        caseload_worker_id=users["social_worker"].id)
        b = ChildRecord(full_name="Secret Child B", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home")
        gone = ChildRecord(full_name="Gone", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           is_deleted=True)
        school = ChildRecord(full_name="School", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([a, b, gone, school])
        db.session.flush()
        uid = users["social_worker"].id
        db.session.add_all([
            CourtHearing(child_record_id=a.id, hearing_at=datetime.now() + timedelta(days=3), court="Court",
                         case_reference="SECRET-REF", created_by=uid),
            CarePlanGoal(child_record_id=a.id, goal="Secret goal text", review_date=date.today() - timedelta(days=2),
                         status="open", created_by=uid),
            MissingChildAlert(child_record_id=b.id, last_seen_at=datetime.now() - timedelta(hours=1),
                              circumstances="Secret circumstances", raised_by=uid),
        ])
        placement = Placement(child_record_id=a.id, outcome="family_reunification", exit_date=date.today(),
                              recorded_by=uid)
        db.session.add(placement)
        db.session.flush()
        db.session.add(AftercareFollowUp(placement_id=placement.id, due_date=date.today(), created_by=uid))
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def test_manager_sees_counts_and_due_items(app):
    html = sign_in(app, "home_manager").get("/home-manager/overview").get_data(as_text=True)
    compact = " ".join(html.split())
    for label, value in (("Children in the home", 2), ("Hearings in the next 14 days", 1),
                         ("Overdue care plan reviews", 1), ("Open missing child alerts", 1),
                         ("Aftercare follow-ups due", 1)):
        assert f'<dt>{label}</dt><dd class="mono">{value}</dd>' in compact


def test_overview_shows_no_names_or_encrypted_text(app):
    html = sign_in(app, "home_manager").get("/home-manager/overview").get_data(as_text=True)
    for secret in ("Secret Child", "SECRET-REF", "Secret goal text", "Secret circumstances"):
        assert secret not in html


def test_every_link_opens_a_page_the_manager_can_read(app):
    import re

    manager = sign_in(app, "home_manager")
    html = manager.get("/home-manager/overview").get_data(as_text=True)
    links = set(re.findall(r'href="(/(?:court|care|missing|placement)/[^"]+)"', html))
    assert links
    for link in links:
        assert manager.get(link).status_code == 200, link


@pytest.mark.parametrize("key", ["social_worker", "legal_officer", "principal"])
def test_other_roles_are_refused(app, key):
    assert sign_in(app, key).get("/home-manager/overview").status_code == 403


def test_administrator_can_open_it(app):
    assert sign_in(app, "administrator").get("/home-manager/overview").status_code == 200
