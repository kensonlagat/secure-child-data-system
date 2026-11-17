"""Placement, reintegration and aftercare (#59)."""

from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.placement import AftercareFollowUp, Placement
from app.models.user import Role, User

PASSWORD = "Password#2026"
ROLES = {"social_worker": "childrens_home", "social_worker2": "childrens_home", "home_manager": "childrens_home",
         "legal_officer": "childrens_home", "administrator": "both"}
PORTAL = {"both": "childrens_home", "childrens_home": "childrens_home"}
TODAY = date.today()


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
                           legal_status="in_state_care", caseload_worker_id=users["social_worker"].id)
        other = ChildRecord(full_name="Other", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                            legal_status="in_state_care", caseload_worker_id=users["social_worker2"].id)
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


def record(app, client, key="MINE", outcome="family_reunification", **extra):
    return client.post(f"/placement/records/{app.config[key]}",
                       data={"outcome": outcome, "exit_date": TODAY.isoformat(),
                             "destination_notes": "Back with grandmother (marker-pl4ce)", **extra})


def legal_status(app, key="MINE"):
    with app.app_context():
        return db.session.get(ChildRecord, app.config[key]).legal_status


def only_placement(app):
    with app.app_context():
        entry = Placement.query.one()
        db.session.expunge(entry)
        return entry


def test_assigned_worker_records_a_placement(app):
    worker = sign_in(app, "social_worker")
    assert record(app, worker).status_code == 302
    assert only_placement(app).outcome == "family_reunification"


@pytest.mark.parametrize("outcome", ["adoption", "foster_care", "family_reunification", "leaving_care"])
def test_exit_never_changes_legal_status(app, outcome):
    """#59 done-when: an exit does not bypass VALID_LEGAL_STATUSES or two-person approval."""
    record(app, sign_in(app, "social_worker"), outcome=outcome)
    assert legal_status(app) == "in_state_care"


def test_adoption_points_to_the_legal_workflow(app):
    worker = sign_in(app, "social_worker")
    record(app, worker, outcome="adoption")
    html = worker.get(f"/placement/records/{app.config['MINE']}").get_data(as_text=True)
    assert "legal status workflow" in html


def test_legal_status_cannot_be_smuggled_through_the_placement_form(app):
    record(app, sign_in(app, "social_worker"), outcome="adoption", legal_status="placed")
    assert legal_status(app) == "in_state_care"


def test_followups_due_are_listed_and_completion_is_audited(app):
    worker = sign_in(app, "social_worker")
    record(app, worker)
    placement_id = only_placement(app).id
    worker.post(f"/placement/placements/{placement_id}/followups", data={"due_date": (TODAY - timedelta(days=1)).isoformat()})
    worker.post(f"/placement/placements/{placement_id}/followups", data={"due_date": (TODAY + timedelta(days=60)).isoformat()})

    due_html = worker.get("/placement/due").get_data(as_text=True)
    assert "1 due" in due_html and "Overdue" in due_html

    with app.app_context():
        first = AftercareFollowUp.query.order_by(AftercareFollowUp.due_date).first().id
    worker.post(f"/placement/followups/{first}/complete", data={"notes": "Doing well (marker-aft3r)"})
    assert "0 due" in worker.get("/placement/due").get_data(as_text=True)
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="aftercare_followup_completed").count() == 1


@pytest.mark.parametrize("key", ["legal_officer", "home_manager"])
def test_legal_officer_and_home_manager_read_only(app, key):
    record(app, sign_in(app, "social_worker"))
    client = sign_in(app, key)
    html = client.get(f"/placement/records/{app.config['MINE']}").get_data(as_text=True)
    assert "marker-pl4ce" in html and 'name="destination_notes"' not in html
    assert record(app, client).status_code == 403
    assert client.get("/placement/due").status_code == 200


@pytest.mark.parametrize("key, record_key", [("social_worker", "OTHER"), ("social_worker2", "MINE"),
                                            ("administrator", "MINE")])
def test_others_get_404(app, key, record_key):
    client = sign_in(app, key)
    assert client.get(f"/placement/records/{app.config[record_key]}").status_code == 404
    assert record(app, client, record_key).status_code == 404


def test_due_list_only_shows_readable_records(app):
    record(app, sign_in(app, "social_worker2"), "OTHER")
    with app.app_context():
        placement_id = Placement.query.one().id
    sign_in(app, "social_worker2").post(f"/placement/placements/{placement_id}/followups",
                                        data={"due_date": TODAY.isoformat()})
    assert "0 due" in sign_in(app, "social_worker").get("/placement/due").get_data(as_text=True)


@pytest.mark.parametrize("bad", [{"outcome": "runaway"}, {"exit_date": ""}, {"destination_notes": "x" * 1001}])
def test_invalid_placements_are_refused(app, bad):
    record(app, sign_in(app, "social_worker"), **bad)
    with app.app_context():
        assert Placement.query.count() == 0


def test_notes_are_ciphertext_and_never_audited(app):
    record(app, sign_in(app, "social_worker"))
    with app.app_context():
        stored = bytes(db.session.execute(text("SELECT destination_notes FROM placements")).scalar())
        details = " ".join(r.details or "" for r in AuditLogEntry.query.all())
    assert b"marker-pl4ce" not in stored and "marker-pl4ce" not in details


def test_placements_are_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert "placements" in APPEND_ONLY_TABLES
