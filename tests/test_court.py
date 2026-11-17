"""Court dates and the legal calendar (#56)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.court import CourtHearing
from app.models.user import Role, User

PASSWORD = "Password#2026"
ROLES = {"legal_officer": "childrens_home", "home_manager": "childrens_home", "social_worker": "childrens_home",
         "social_worker2": "childrens_home", "administrator": "both", "teacher": "school"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}
SOON = datetime.now().replace(microsecond=0, second=0) + timedelta(days=3)


def hearing_form(when=SOON, **extra):
    return {"hearing_at": when.strftime("%Y-%m-%dT%H:%M"), "court": "Milimani Children's Court",
            "case_reference": "CR/77/2026 (marker-c0urt)", **extra}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for key, mode in ROLES.items():
            role_name = "social_worker" if key.startswith("social_worker") else key
            role = Role.query.filter_by(name=role_name).first() or Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        mine = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           caseload_worker_id=users["social_worker"].id)
        other = ChildRecord(full_name="Other", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                            caseload_worker_id=users["social_worker2"].id)
        db.session.add_all([mine, other])
        db.session.commit()
        application.config.update(MINE=mine.id, OTHER=other.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def add(app, client, key="MINE", **form):
    return client.post(f"/court/records/{app.config[key]}", data=hearing_form(**form))


def count(app):
    with app.app_context():
        return CourtHearing.query.count()


def test_legal_officer_manages_hearings(app):
    legal = sign_in(app, "legal_officer")
    assert add(app, legal).status_code == 302
    with app.app_context():
        hearing_id = CourtHearing.query.one().id
    legal.post(f"/court/hearings/{hearing_id}", data=hearing_form(outcome="Adjourned (marker-0utc)",
                                                                  next_date=(SOON + timedelta(days=30)).date().isoformat()))
    with app.app_context():
        hearing = CourtHearing.query.one()
        assert hearing.outcome == "Adjourned (marker-0utc)" and hearing.next_date is not None
        assert AuditLogEntry.query.filter_by(action="court_hearing_updated").count() == 1


@pytest.mark.parametrize("key", ["home_manager", "social_worker"])
def test_home_manager_and_assigned_social_worker_read_only(app, key):
    add(app, sign_in(app, "legal_officer"))
    client = sign_in(app, key)
    html = client.get(f"/court/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-c0urt" in html and 'name="case_reference"' not in html
    assert add(app, client).status_code == 403
    assert count(app) == 1


@pytest.mark.parametrize("key, record_key", [("social_worker", "OTHER"), ("social_worker2", "MINE"),
                                            ("administrator", "MINE"), ("teacher", "MINE")])
def test_others_get_404(app, key, record_key):
    client = sign_in(app, key)
    assert client.get(f"/court/records/{app.config[record_key]}").status_code == 404
    assert add(app, client, record_key).status_code == 404


def test_upcoming_lists_per_child_and_overall_within_scope(app):
    legal = sign_in(app, "legal_officer")
    add(app, legal)
    add(app, legal, "OTHER", when=SOON + timedelta(days=1))
    add(app, legal, when=SOON + timedelta(days=40))  # beyond the 14-day window
    add(app, legal, when=datetime.now() - timedelta(days=2))  # past

    overall_legal = legal.get("/court/upcoming").get_data(as_text=True)
    overall_worker = sign_in(app, "social_worker").get("/court/upcoming").get_data(as_text=True)
    per_child = legal.get(f"/court/records/{app.config['MINE']}").get_data(as_text=True)

    assert "2 upcoming" in overall_legal
    assert "1 upcoming" in overall_worker  # only their own caseload
    assert "1 hearing in the" in per_child


def test_upcoming_is_refused_for_other_roles(app):
    assert sign_in(app, "teacher").get("/court/upcoming").status_code == 403


@pytest.mark.parametrize("bad", [{"court": ""}, {"case_reference": ""}, {"case_reference": "x" * 61},
                                 {"hearing_at": "soon"},
                                 {"next_date": (SOON - timedelta(days=1)).date().isoformat()}])
def test_invalid_hearings_are_refused(app, bad):
    form = hearing_form()
    form.update(bad)
    sign_in(app, "legal_officer").post(f"/court/records/{app.config['MINE']}", data=form)
    assert count(app) == 0


def test_reference_and_outcome_are_ciphertext_and_never_audited(app):
    legal = sign_in(app, "legal_officer")
    add(app, legal, outcome="Committed (marker-0utc)")
    with app.app_context():
        stored = b"".join(bytes(v) for v in db.session.execute(text("SELECT case_reference, outcome FROM court_hearings")).one())
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    for marker in ("marker-c0urt", "marker-0utc"):
        assert marker.encode() not in stored and marker not in details
