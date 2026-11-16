"""Principal overview (#53): aggregates only."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.attendance import AttendanceMark, AttendanceRegister
from app.models.child_record import ChildRecord
from app.models.clinic import ClinicVisit
from app.models.user import Role, User
from app.services import overview_service
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"principal": "school", "administrator": "both", "teacher": "school", "school_nurse": "school",
         "home_manager": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for role_name, mode in ROLES.items():
            role = Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[role_name] = User(email=f"{role_name}@example.com", full_name=role_name, phone_number="+254700000001",
                                    password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[role_name])
        db.session.flush()
        amina = ChildRecord(full_name="Amina Secretname", date_of_birth=date(2014, 1, 1), institution_mode="school")
        brian = ChildRecord(full_name="Brian Secretname", date_of_birth=date(2014, 1, 1), institution_mode="school")
        gone = ChildRecord(full_name="Gone", date_of_birth=date(2014, 1, 1), institution_mode="school", is_deleted=True)
        db.session.add_all([amina, brian, gone])
        db.session.flush()
        c6a = put_in_class("Grade 6A", children=[amina, brian, gone], teachers=[users["teacher"]])
        register = AttendanceRegister(class_id=c6a.id, register_date=date.today(), taken_by=users["teacher"].id)
        db.session.add(register)
        db.session.flush()
        db.session.add_all([AttendanceMark(register_id=register.id, child_record_id=amina.id, status="present"),
                            AttendanceMark(register_id=register.id, child_record_id=brian.id, status="absent"),
                            AttendanceMark(register_id=register.id, child_record_id=gone.id, status="absent")])
        db.session.add_all([ClinicVisit(child_record_id=amina.id, visited_at=datetime.now() - timedelta(minutes=5),
                                        complaint="Secret complaint", treatment="Secret treatment",
                                        recorded_by=users["school_nurse"].id),
                            ClinicVisit(child_record_id=gone.id, visited_at=datetime.now() - timedelta(minutes=5),
                                        complaint="x", treatment="y", recorded_by=users["school_nurse"].id)])
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, role_name):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{role_name}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[role_name]]}).status_code == 302
    return client


def test_attendance_trend_counts_exclude_deleted_records(app):
    with app.app_context():
        today = overview_service.attendance_trend()[date.today()]
    assert today == {"present": 1, "absent": 1, "late": 0, "excused": 0}


def test_clinic_activity_counts_this_week(app):
    with app.app_context():
        weeks = overview_service.clinic_activity()
    assert len(weeks) == 4 and weeks[-1][1] == 1  # the deleted record's visit is excluded


def test_principal_sees_counts_but_no_names_or_clinical_text(app):
    response = sign_in(app, "principal").get("/principal/overview")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Attendance, last 14 days" in html and "Clinic activity" in html
    for secret in ("Secretname", "Secret complaint", "Secret treatment", "Grade 6A"):
        assert secret not in html
    assert "/clinic/records/" not in html and "/school/records/" not in html.replace('href="/school/records"', "")


def test_administrator_can_open_the_overview(app):
    assert sign_in(app, "administrator").get("/principal/overview").status_code == 200


@pytest.mark.parametrize("role_name", ["teacher", "school_nurse", "home_manager"])
def test_other_roles_are_refused(app, role_name):
    assert sign_in(app, role_name).get("/principal/overview").status_code == 403


def test_viewing_is_audited(app):
    from app.models.audit_log import AuditLogEntry

    sign_in(app, "principal").get("/principal/overview")
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="principal_overview_viewed").count() == 1
