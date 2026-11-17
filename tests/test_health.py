"""Health and medication records (#57)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.health import HealthEntry, MedicationAdministration, MedicationSchedule
from app.models.user import Role, User
from app.services import health_service

PASSWORD = "Password#2026"
ROLES = {"social_worker": "childrens_home", "social_worker2": "childrens_home", "home_manager": "childrens_home",
         "administrator": "both", "legal_officer": "childrens_home", "teacher": "school"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}


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
        application.config.update(MINE=mine.id, OTHER=other.id, WORKER=users["social_worker"].id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def schedule_form(start=None, times="08:00", **extra):
    return {"medicine": "Amoxicillin (marker-m3d)", "dose": "250mg", "daily_times": times,
            "start_date": (start or date.today() - timedelta(days=2)).isoformat(), **extra}


def add_schedule(app, client, key="MINE", **form):
    return client.post(f"/health/records/{app.config[key]}/schedules", data=schedule_form(**form))


def only_schedule(app):
    with app.app_context():
        schedule = MedicationSchedule.query.one()
        db.session.expunge(schedule)
        return schedule


def test_social_worker_records_entries_schedules_and_doses(app):
    worker = sign_in(app, "social_worker")
    worker.post(f"/health/records/{app.config['MINE']}/entries",
                data={"entry_type": "immunisation", "entry_at": "2026-01-10T09:00", "details": "Measles (marker-h3alth)"})
    add_schedule(app, worker)
    schedule = only_schedule(app)
    due = datetime.combine(date.today() - timedelta(days=1), datetime.strptime("08:00", "%H:%M").time())
    worker.post(f"/health/schedules/{schedule.id}/doses", data={"scheduled_for": due.isoformat(), "outcome": "given"})
    with app.app_context():
        assert HealthEntry.query.count() == 1
        assert MedicationAdministration.query.one().outcome == "given"


def test_missed_scheduled_dose_is_visible_to_the_home_manager(app):
    add_schedule(app, sign_in(app, "social_worker"), start=date.today() - timedelta(days=2), times="08:00")
    html = sign_in(app, "home_manager").get(f"/health/records/{app.config['MINE']}").get_data(as_text=True)
    assert "missed scheduled dose" in html
    with app.app_context():
        missed = health_service.missed_doses([app.config["MINE"]], now=datetime.combine(date.today(), datetime.min.time())
                                             + timedelta(hours=23))
    assert len(missed) == 3  # two past days plus today's 08:00, all unlogged


def test_a_logged_dose_is_not_missed(app):
    worker = sign_in(app, "social_worker")
    add_schedule(app, worker, start=date.today() - timedelta(days=1), times="08:00")
    schedule = only_schedule(app)
    due = datetime.combine(date.today() - timedelta(days=1), datetime.strptime("08:00", "%H:%M").time())
    worker.post(f"/health/schedules/{schedule.id}/doses", data={"scheduled_for": due.isoformat(), "outcome": "refused"})
    with app.app_context():
        missed = health_service.missed_doses([app.config["MINE"]], now=due + timedelta(hours=3))
    assert missed == []


def test_a_dose_cannot_be_recorded_twice_or_off_schedule(app):
    worker = sign_in(app, "social_worker")
    add_schedule(app, worker)
    schedule = only_schedule(app)
    due = datetime.combine(date.today(), datetime.strptime("08:00", "%H:%M").time())
    for _ in range(2):
        worker.post(f"/health/schedules/{schedule.id}/doses", data={"scheduled_for": due.isoformat(), "outcome": "given"})
    worker.post(f"/health/schedules/{schedule.id}/doses",
                data={"scheduled_for": due.replace(hour=13).isoformat(), "outcome": "given"})
    with app.app_context():
        assert MedicationAdministration.query.count() == 1


def test_stopped_schedules_raise_no_missed_doses(app):
    worker = sign_in(app, "social_worker")
    add_schedule(app, worker)
    worker.post(f"/health/schedules/{only_schedule(app).id}/stop")
    with app.app_context():
        assert health_service.missed_doses([app.config["MINE"]]) == []
        assert AuditLogEntry.query.filter_by(action="medication_schedule_stopped").count() == 1


def test_home_manager_reads_but_cannot_write(app):
    manager = sign_in(app, "home_manager")
    assert add_schedule(app, manager).status_code == 403
    assert manager.get(f"/health/records/{app.config['MINE']}").status_code == 200


def test_administrator_writes(app):
    assert add_schedule(app, sign_in(app, "administrator")).status_code == 302
    only_schedule(app)


@pytest.mark.parametrize("key, record_key", [("social_worker", "OTHER"), ("legal_officer", "MINE"), ("teacher", "MINE")])
def test_others_get_404(app, key, record_key):
    client = sign_in(app, key)
    assert client.get(f"/health/records/{app.config[record_key]}").status_code == 404
    assert add_schedule(app, client, record_key).status_code == 404


@pytest.mark.parametrize("bad", [{"daily_times": "8am"}, {"daily_times": ""}, {"medicine": ""},
                                 {"end_date": "2000-01-01"}])
def test_invalid_schedules_are_refused(app, bad):
    add_schedule(app, sign_in(app, "social_worker"), **bad)
    with app.app_context():
        assert MedicationSchedule.query.count() == 0


def test_health_text_is_ciphertext_and_never_audited(app):
    worker = sign_in(app, "social_worker")
    worker.post(f"/health/records/{app.config['MINE']}/entries",
                data={"entry_type": "appointment", "entry_at": "2026-01-10T09:00", "details": "Dentist (marker-h3alth)"})
    add_schedule(app, worker)
    with app.app_context():
        stored = bytes(db.session.execute(text("SELECT details FROM health_entries")).scalar())
        stored += bytes(db.session.execute(text("SELECT medicine FROM medication_schedules")).scalar())
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    for marker in ("marker-h3alth", "marker-m3d"):
        assert marker.encode() not in stored and marker not in details


def test_health_log_tables_are_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert {"health_entries", "medication_administrations"} <= set(APPEND_ONLY_TABLES)
