"""Care plan goals and case notes (#55)."""

from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.care_plan import CarePlanGoal, CaseNote
from app.models.child_record import ChildRecord
from app.models.user import Role, User
from app.services import care_plan_service

PASSWORD = "Password#2026"
ROLES = {"social_worker": "childrens_home", "social_worker2": "childrens_home", "home_manager": "childrens_home",
         "legal_officer": "childrens_home", "administrator": "both", "teacher": "school"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}
TODAY = date.today()
NOTE = {"note_date": TODAY.isoformat(), "category": "welfare", "body": "Settling in well (marker-n0te)",
        "legal_summary": "Court report requested (marker-l3gal)"}


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


def add_goal(app, client, key="MINE", review=TODAY + timedelta(days=30), goal="Attend school daily (marker-g0al)"):
    return client.post(f"/care/records/{app.config[key]}/goals", data={"goal": goal, "review_date": review.isoformat()})


def add_note(app, client, key="MINE", **overrides):
    return client.post(f"/care/records/{app.config[key]}/notes", data={**NOTE, **overrides})


def counts(app):
    with app.app_context():
        return CarePlanGoal.query.count(), CaseNote.query.count()


def test_assigned_social_worker_writes_goals_and_notes(app):
    worker = sign_in(app, "social_worker")
    add_goal(app, worker)
    add_note(app, worker)
    assert counts(app) == (1, 1)
    html = worker.get(f"/care/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-g0al" in html and "marker-n0te" in html


@pytest.mark.parametrize("key", ["social_worker2", "administrator", "home_manager", "legal_officer"])
def test_only_the_assigned_social_worker_can_write(app, key):
    client = sign_in(app, key)
    responses = [add_goal(app, client).status_code, add_note(app, client).status_code]
    assert all(code in (403, 404) for code in responses)
    assert counts(app) == (0, 0)


def test_home_manager_reads_everything(app):
    worker = sign_in(app, "social_worker")
    add_goal(app, worker)
    add_note(app, worker)
    html = sign_in(app, "home_manager").get(f"/care/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-g0al" in html and "marker-n0te" in html and 'name="body"' not in html


def test_legal_officer_sees_only_legal_summaries(app):
    worker = sign_in(app, "social_worker")
    add_goal(app, worker)
    add_note(app, worker)
    add_note(app, worker, body="No legal angle (marker-pr1v)", legal_summary="")
    html = sign_in(app, "legal_officer").get(f"/care/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-l3gal" in html
    for hidden in ("marker-n0te", "marker-g0al", "marker-pr1v"):
        assert hidden not in html
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="legal_summaries_viewed").count() == 1


@pytest.mark.parametrize("key, record_key", [("social_worker", "OTHER"), ("teacher", "MINE"), ("administrator", "MINE")])
def test_out_of_scope_reads_are_404(app, key, record_key):
    assert sign_in(app, key).get(f"/care/records/{app.config[record_key]}").status_code == 404


def test_overdue_review_is_flagged(app):
    worker = sign_in(app, "social_worker")
    add_goal(app, worker, review=TODAY - timedelta(days=1), goal="Overdue goal")
    add_goal(app, worker, review=TODAY + timedelta(days=5), goal="Fine goal")
    html = worker.get(f"/care/records/{app.config['MINE']}").get_data(as_text=True)
    assert html.count("Review overdue") == 1
    with app.app_context():
        assert care_plan_service.overdue_goals_query().count() == 1


def test_achieved_goals_are_not_overdue_and_updates_are_audited(app):
    worker = sign_in(app, "social_worker")
    add_goal(app, worker, review=TODAY - timedelta(days=1))
    with app.app_context():
        goal_id = CarePlanGoal.query.one().id
    worker.post(f"/care/goals/{goal_id}", data={"status": "achieved", "review_date": (TODAY - timedelta(days=1)).isoformat()})
    with app.app_context():
        assert care_plan_service.overdue_goals_query().count() == 0
        assert AuditLogEntry.query.filter_by(action="care_goal_updated").count() == 1


def test_other_worker_cannot_update_a_goal(app):
    add_goal(app, sign_in(app, "social_worker"))
    with app.app_context():
        goal_id = CarePlanGoal.query.one().id
    response = sign_in(app, "social_worker2").post(f"/care/goals/{goal_id}",
                                                   data={"status": "discontinued", "review_date": TODAY.isoformat()})
    assert response.status_code == 404
    with app.app_context():
        assert CarePlanGoal.query.one().status == "open"


@pytest.mark.parametrize("bad", [{"category": "gossip"}, {"body": ""}, {"body": "x" * 4001},
                                 {"note_date": (TODAY + timedelta(days=1)).isoformat()}, {"legal_summary": "x" * 501}])
def test_invalid_notes_are_refused(app, bad):
    add_note(app, sign_in(app, "social_worker"), **bad)
    assert counts(app) == (0, 0)


def test_text_is_ciphertext_at_rest_and_never_audited(app):
    worker = sign_in(app, "social_worker")
    add_goal(app, worker)
    add_note(app, worker)
    with app.app_context():
        stored = b"".join(bytes(v) for v in db.session.execute(text("SELECT goal FROM care_plan_goals")).one())
        stored += b"".join(bytes(v) for v in db.session.execute(text("SELECT body, legal_summary FROM case_notes")).one())
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    for marker in ("marker-g0al", "marker-n0te", "marker-l3gal"):
        assert marker.encode() not in stored and marker not in details


def test_case_notes_are_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert "case_notes" in APPEND_ONLY_TABLES
