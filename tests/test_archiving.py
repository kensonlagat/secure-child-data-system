"""Leaving, transfer and archiving (#64): archived records vanish from every day-to-day view,
including the lookups that bypass get_accessible_records, are read-only, and are never deleted."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.attendance import AttendanceMark, AttendanceRegister
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.clinic import ClinicVisit
from app.models.missing import MissingChildAlert
from app.models.user import Role, User
from app.services import access_service, attendance_service, overview_service
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
         "social_worker": "childrens_home", "home_manager": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}


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
        staying = ChildRecord(full_name="Staying Pupil", date_of_birth=date(2014, 1, 1), institution_mode="school")
        leaving = ChildRecord(full_name="Leaving Pupil", date_of_birth=date(2014, 1, 1), institution_mode="school")
        home_staying = ChildRecord(full_name="Home Staying", date_of_birth=date(2012, 1, 1),
                                   institution_mode="childrens_home", caseload_worker_id=users["social_worker"].id)
        home_leaving = ChildRecord(full_name="Home Leaving", date_of_birth=date(2012, 1, 1),
                                   institution_mode="childrens_home", caseload_worker_id=users["social_worker"].id)
        db.session.add_all([staying, leaving, home_staying, home_leaving])
        db.session.flush()
        c6a = put_in_class("Grade 6A", children=[staying, leaving], teachers=[users["teacher"]])
        register = AttendanceRegister(class_id=c6a.id, register_date=date.today(), taken_by=users["teacher"].id)
        db.session.add(register)
        db.session.flush()
        db.session.add_all([AttendanceMark(register_id=register.id, child_record_id=c.id, status="present")
                            for c in (staying, leaving)])
        db.session.add_all([ClinicVisit(child_record_id=c.id, visited_at=datetime.now() - timedelta(minutes=5),
                                        complaint="x", treatment="y", recorded_by=users["school_nurse"].id)
                            for c in (staying, leaving)])
        db.session.add(MissingChildAlert(child_record_id=home_leaving.id, last_seen_at=datetime.now(),
                                         circumstances="c", raised_by=users["social_worker"].id))
        db.session.commit()
        application.config.update(STAYING=staying.id, LEAVING=leaving.id, HOME_STAYING=home_staying.id,
                                  HOME_LEAVING=home_leaving.id, C6A=c6a.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302
    return client


def archive(app, key="LEAVING", client=None):
    client = client or sign_in(app, "administrator")
    return client.post(f"/admin/records/{app.config[key]}/archive",
                       data={"leave_reason": "transferred", "leave_date": date.today().isoformat()})


def user(app, key):
    return User.query.filter_by(email=f"{key}@example.com").one()


# --- Archive, restore, no hard delete ---------------------------------------------------------


def test_archive_hides_the_record_from_day_to_day_lists_and_keeps_it(app):
    archive(app)
    for key, path in (("teacher", "/school/records"), ("administrator", "/school/records")):
        ids = {r["id"] for r in sign_in(app, key).get(path, headers={"Accept": "application/json"}).get_json()["items"]}
        assert app.config["LEAVING"] not in ids and app.config["STAYING"] in ids
    with app.app_context():
        assert db.session.get(ChildRecord, app.config["LEAVING"]) is not None  # no hard delete


def test_archive_view_is_admin_only_and_restore_brings_it_back(app):
    archive(app)
    admin = sign_in(app, "administrator")
    assert "Leaving Pupil" in admin.get("/admin/archive").get_data(as_text=True)
    assert sign_in(app, "teacher").get("/admin/archive").status_code == 403
    admin.post(f"/admin/records/{app.config['LEAVING']}/restore")
    with app.app_context():
        assert db.session.get(ChildRecord, app.config["LEAVING"]).is_archived is False
        actions = [r.action for r in AuditLogEntry.query.order_by(AuditLogEntry.id)]
    assert "record_archived" in actions and "record_restored" in actions


def test_only_administrators_archive(app):
    assert archive(app, client=sign_in(app, "teacher")).status_code == 403
    with app.app_context():
        assert db.session.get(ChildRecord, app.config["LEAVING"]).is_archived is False


def test_archived_records_are_read_only_for_everyone(app):
    archive(app)
    with app.app_context():
        record = db.session.get(ChildRecord, app.config["LEAVING"])
        for key in ROLES:
            assert access_service.get_writable_fields(user(app, key), record) == []
    response = sign_in(app, "administrator").patch(f"/school/records/{app.config['LEAVING']}", json={"full_name": "X"})
    assert response.status_code == 404


def test_archiving_needs_a_reason_and_a_past_date(app):
    admin = sign_in(app, "administrator")
    admin.post(f"/admin/records/{app.config['LEAVING']}/archive", data={"leave_reason": "vanished",
                                                                        "leave_date": date.today().isoformat()})
    admin.post(f"/admin/records/{app.config['LEAVING']}/archive", data={
        "leave_reason": "transferred", "leave_date": (date.today() + timedelta(days=1)).isoformat()})
    with app.app_context():
        assert db.session.get(ChildRecord, app.config["LEAVING"]).is_archived is False


# --- Lookups that bypass get_accessible_records also exclude archived records ------------------


def test_pickup_lookup_excludes_archived(app):
    archive(app)
    with app.app_context():
        assert access_service.get_record_for_pickup(user(app, "principal"), app.config["LEAVING"]) is None
        assert access_service.get_record_for_pickup(user(app, "principal"), app.config["STAYING"]) is not None


def resolve_open_alert(app):
    with app.app_context():
        alert = MissingChildAlert.query.filter_by(child_record_id=app.config["HOME_LEAVING"]).one()
        alert.status, alert.found_at, alert.resolution_notes = "resolved", datetime.now(), "Found"
        db.session.commit()


def test_missing_alert_lookup_excludes_archived(app):
    resolve_open_alert(app)  # archiving is refused while an alert is open
    archive(app, "HOME_LEAVING")
    with app.app_context():
        assert access_service.get_record_for_missing_alert(user(app, "social_worker"), app.config["HOME_LEAVING"]) is None
        assert access_service.get_record_for_missing_alert(user(app, "social_worker"),
                                                           app.config["HOME_STAYING"]) is not None


def test_attendance_register_excludes_archived(app):
    archive(app)
    from app.models.school_class import SchoolClass

    with app.app_context():
        children = attendance_service.class_children(db.session.get(SchoolClass, app.config["C6A"]))
        assert [c.id for c in children] == [app.config["STAYING"]]


def test_principal_counts_exclude_archived(app):
    archive(app)
    with app.app_context():
        assert sum(overview_service.attendance_trend()[date.today()].values()) == 1
        assert overview_service.clinic_activity()[-1][1] == 1


def test_archiving_is_refused_while_a_missing_alert_is_open(app):
    admin = sign_in(app, "administrator")
    response = archive(app, "HOME_LEAVING", client=admin)
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(ChildRecord, app.config["HOME_LEAVING"]).is_archived is False
        assert AuditLogEntry.query.filter_by(action="record_archive_refused").count() == 1
    page = admin.get(f"/admin/records/{app.config['HOME_LEAVING']}/archive")  # same session shows the message
    assert "open missing alert" in page.get_data(as_text=True)
    overview = " ".join(sign_in(app, "home_manager").get("/home-manager/overview").get_data(as_text=True).split())
    assert '<dt>Open missing child alerts</dt><dd class="mono">1</dd>' in overview  # still on the manager's screen


def test_home_manager_overview_excludes_archived(app):
    resolve_open_alert(app)  # archiving is refused while the alert is open
    archive(app, "HOME_LEAVING")
    with app.app_context():
        assert db.session.get(ChildRecord, app.config["HOME_LEAVING"]).is_archived is True
    html = " ".join(sign_in(app, "home_manager").get("/home-manager/overview").get_data(as_text=True).split())
    assert '<dt>Children in the home</dt><dd class="mono">1</dd>' in html
    assert '<dt>Open missing child alerts</dt><dd class="mono">0</dd>' in html
