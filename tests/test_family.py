"""Family contact, visits and tracing (#58)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.family import FamilyTracing, FamilyVisit
from app.models.user import Role, User

PASSWORD = "Password#2026"
ROLES = {"social_worker": "childrens_home", "social_worker2": "childrens_home", "home_manager": "childrens_home",
         "administrator": "both", "legal_officer": "childrens_home"}
PORTAL = {"both": "childrens_home", "childrens_home": "childrens_home"}


def visit_form(days_ago=1, **extra):
    return {"visit_at": (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M"),
            "visitor_name": "Mary Atieno (marker-v1s1t)", "relationship": "mother", "supervised": "yes",
            "notes": "Warm visit (marker-n0tes)", **extra}


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


def add_visit(app, client, key="MINE", **form):
    return client.post(f"/family/records/{app.config[key]}/visits", data=visit_form(**form))


def count(app):
    with app.app_context():
        return FamilyVisit.query.count()


def test_assigned_worker_records_visits_listed_chronologically(app):
    worker = sign_in(app, "social_worker")
    add_visit(app, worker, days_ago=1, visitor_name="Later Visitor")
    add_visit(app, worker, days_ago=5, visitor_name="Earlier Visitor")
    html = worker.get(f"/family/records/{app.config['MINE']}").get_data(as_text=True)
    assert html.index("Earlier Visitor") < html.index("Later Visitor")
    assert count(app) == 2


def test_tracing_status_changes_are_audited(app):
    worker = sign_in(app, "social_worker")
    worker.post(f"/family/records/{app.config['MINE']}/tracing", data={"status": "in_progress"})
    worker.post(f"/family/records/{app.config['MINE']}/tracing", data={"status": "family_found"})
    with app.app_context():
        assert FamilyTracing.query.one().status == "family_found"
        details = [r.details for r in AuditLogEntry.query.filter_by(action="family_tracing_updated")]
    assert details == ["Family tracing none -> in_progress", "Family tracing in_progress -> family_found"]


def test_home_manager_reads_only(app):
    add_visit(app, sign_in(app, "social_worker"))
    manager = sign_in(app, "home_manager")
    html = manager.get(f"/family/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-v1s1t" in html and 'name="visitor_name"' not in html
    assert add_visit(app, manager).status_code == 403
    assert count(app) == 1


@pytest.mark.parametrize("key, record_key", [("social_worker", "OTHER"), ("administrator", "MINE"),
                                            ("legal_officer", "MINE")])
def test_others_get_404(app, key, record_key):
    client = sign_in(app, key)
    assert client.get(f"/family/records/{app.config[record_key]}").status_code == 404
    assert add_visit(app, client, record_key).status_code == 404


@pytest.mark.parametrize("bad", [{"visitor_name": ""}, {"relationship": "friend"}, {"supervised": "maybe"},
                                 {"visit_at": (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")},
                                 {"notes": "x" * 2001}])
def test_invalid_visits_are_refused(app, bad):
    add_visit(app, sign_in(app, "social_worker"), **bad)
    assert count(app) == 0


def test_names_and_notes_are_ciphertext_and_never_audited(app):
    add_visit(app, sign_in(app, "social_worker"))
    with app.app_context():
        row = db.session.execute(text("SELECT visitor_name, notes FROM family_visits")).one()
        details = " ".join(r.details or "" for r in AuditLogEntry.query.all())
    stored = b"".join(bytes(v) for v in row)
    for marker in ("marker-v1s1t", "marker-n0tes", "Atieno"):
        assert marker.encode() not in stored and marker not in details


def test_family_visits_are_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert "family_visits" in APPEND_ONLY_TABLES
