"""Daily attendance registers and absence alerts (#50)."""

from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.attendance import AbsenceAlert, AttendanceCorrection, AttendanceMark, AttendanceRegister
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.school_class import SchoolClass
from app.models.user import Role, User
from app.services.attendance_service import ABSENCE_SMS_TEXT
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "teacher2": "school", "principal": "school",
         "school_nurse": "school"}
TODAY = date.today()


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
        for key, mode in ROLES.items():
            role_name = "teacher" if key.startswith("teacher") else key
            role = Role.query.filter_by(name=role_name).first() or Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[key])
        db.session.flush()
        amina = ChildRecord(full_name="Amina Achieng", date_of_birth=date(2014, 1, 1), institution_mode="school",
                            guardian_contact="+254711000001")
        brian = ChildRecord(full_name="Brian Kip", date_of_birth=date(2014, 1, 1), institution_mode="school")
        gone = ChildRecord(full_name="Deleted Child", date_of_birth=date(2014, 1, 1), institution_mode="school",
                           is_deleted=True)
        other = ChildRecord(full_name="Other Class", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([amina, brian, gone, other])
        db.session.flush()
        c6a = put_in_class("Grade 6A", children=[amina, brian, gone], teachers=[users["teacher"]])
        c7c = put_in_class("Grade 7C", children=[other], teachers=[users["teacher2"]])
        db.session.commit()
        application.config.update(C6A=c6a.id, C7C=c7c.id, AMINA=amina.id, BRIAN=brian.id, GONE=gone.id,
                                  OTHER=other.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": "school"}).status_code == 302
    return client


def submit(app, client, day=TODAY, reason=None, class_key="C6A", **statuses):
    data = {f"status_{app.config[key.upper()]}": value for key, value in statuses.items()}
    if reason is not None:
        data["reason"] = reason
    return client.post(f"/attendance/classes/{app.config[class_key]}?date={day.isoformat()}", data=data)


def mark_of(app, child_key, day=TODAY):
    with app.app_context():
        mark = (AttendanceMark.query.join(AttendanceRegister)
                .filter(AttendanceRegister.register_date == day,
                        AttendanceMark.child_record_id == app.config[child_key]).first())
        return mark.status if mark else None


def audit(app, action):
    with app.app_context():
        return [row.details for row in AuditLogEntry.query.filter_by(action=action).order_by(AuditLogEntry.id)]


# --- Who can mark and read --------------------------------------------------------------------


def test_teacher_marks_their_own_class(app, sms):
    response = submit(app, sign_in(app, "teacher"), amina="present", brian="late")
    assert response.status_code == 302
    assert (mark_of(app, "AMINA"), mark_of(app, "BRIAN")) == ("present", "late")
    assert audit(app, "attendance_taken") == [f"Register {TODAY.isoformat()}: present 1, absent 0, late 1, excused 0"]


def test_teacher_cannot_open_or_mark_another_class(app, sms):
    teacher = sign_in(app, "teacher")
    assert teacher.get(f"/attendance/classes/{app.config['C7C']}").status_code == 404
    assert submit(app, teacher, class_key="C7C", other="absent").status_code == 404
    assert mark_of(app, "OTHER") is None
    assert len(audit(app, "access_denied")) >= 1


def test_archived_class_cannot_be_marked_by_its_teacher(app, sms):
    with app.app_context():
        db.session.get(SchoolClass, app.config["C6A"]).is_active = False
        db.session.commit()
    assert submit(app, sign_in(app, "teacher"), amina="present").status_code == 404


def test_principal_reads_but_cannot_mark(app, sms):
    principal = sign_in(app, "principal")
    assert principal.get(f"/attendance/classes/{app.config['C6A']}").status_code == 200
    assert submit(app, principal, amina="absent").status_code == 403
    assert mark_of(app, "AMINA") is None


def test_clinical_officer_has_no_attendance_access(app, sms):
    nurse = sign_in(app, "school_nurse")
    assert nurse.get("/attendance/").status_code == 403
    assert nurse.get(f"/attendance/classes/{app.config['C6A']}").status_code == 404


def test_register_excludes_deleted_children(app, sms):
    html = sign_in(app, "teacher").get(f"/attendance/classes/{app.config['C6A']}").get_data(as_text=True)
    assert "Amina Achieng" in html and "Deleted Child" not in html
    assert submit(app, sign_in(app, "teacher"), gone="present").status_code == 302  # refused with a message
    assert mark_of(app, "GONE") is None


# --- Same day, past days, future days --------------------------------------------------------------


def test_same_day_changes_need_no_reason_and_leave_no_correction(app, sms):
    teacher = sign_in(app, "teacher")
    submit(app, teacher, amina="present")
    submit(app, teacher, amina="late")
    assert mark_of(app, "AMINA") == "late"
    with app.app_context():
        assert AttendanceCorrection.query.count() == 0


def test_changing_a_past_day_needs_a_reason(app, sms):
    teacher = sign_in(app, "teacher")
    yesterday = TODAY - timedelta(days=1)
    submit(app, teacher, day=yesterday, reason="Register taken late", amina="present")

    submit(app, teacher, day=yesterday, amina="excused")  # no reason
    assert mark_of(app, "AMINA", yesterday) == "present"

    submit(app, teacher, day=yesterday, reason="Doctor's note arrived (marker-r34s)", amina="excused")
    assert mark_of(app, "AMINA", yesterday) == "excused"
    with app.app_context():
        corrections = AttendanceCorrection.query.order_by(AttendanceCorrection.id).all()
        assert [(c.old_status, c.new_status) for c in corrections] == [("unmarked", "present"), ("present", "excused")]
        stored = db.session.execute(text("SELECT reason FROM attendance_corrections ORDER BY id DESC")).scalar()
    assert b"marker-r34s" not in bytes(stored)
    assert all("marker-r34s" not in (d or "") for d in audit(app, "attendance_corrected"))


def test_future_registers_are_refused(app, sms):
    submit(app, sign_in(app, "teacher"), day=TODAY + timedelta(days=1), amina="present")
    assert mark_of(app, "AMINA", TODAY + timedelta(days=1)) is None


def test_unknown_status_and_children_from_other_classes_are_refused(app, sms):
    teacher = sign_in(app, "teacher")
    submit(app, teacher, amina="on_holiday")
    submit(app, teacher, other="present")
    assert mark_of(app, "AMINA") is None and mark_of(app, "OTHER") is None


# --- Absence alerts --------------------------------------------------------------------------------


def absent_on(app, client, days_ago):
    return submit(app, client, day=TODAY - timedelta(days=days_ago), reason="Back-filled", amina="absent")


def test_alert_fires_once_when_the_threshold_is_reached(app, sms):
    teacher = sign_in(app, "teacher")
    absent_on(app, teacher, 3)
    absent_on(app, teacher, 2)
    assert sms == []
    absent_on(app, teacher, 1)
    absent_on(app, teacher, 0)  # a fourth absence in the same window sends nothing more

    assert sms == [("+254711000001", ABSENCE_SMS_TEXT)]
    with app.app_context():
        assert [a.outcome for a in AbsenceAlert.query.all()] == ["sent"]
    assert audit(app, "absence_alert_sent") == ["3 absences in 30 days"]


def test_alert_text_names_nothing(app, sms):
    assert "Amina" not in ABSENCE_SMS_TEXT and "6A" not in ABSENCE_SMS_TEXT and "Grade" not in ABSENCE_SMS_TEXT


def test_sms_failure_is_recorded_and_the_register_still_saves(app, monkeypatch):
    def broken(phone, message):
        raise RuntimeError("provider down")

    monkeypatch.setattr("app.services.sms_service.send_sms", broken)
    teacher = sign_in(app, "teacher")
    for days_ago in (2, 1, 0):
        absent_on(app, teacher, days_ago)
    assert mark_of(app, "AMINA") == "absent"
    with app.app_context():
        assert [a.outcome for a in AbsenceAlert.query.all()] == ["failed"]


def test_no_guardian_contact_is_recorded_without_sending(app, sms):
    teacher = sign_in(app, "teacher")
    for days_ago in (2, 1, 0):
        submit(app, teacher, day=TODAY - timedelta(days=days_ago), reason="Back-filled", brian="absent")
    assert sms == []
    with app.app_context():
        assert [a.outcome for a in AbsenceAlert.query.all()] == ["no_contact"]


def test_attendance_append_only_tables_are_registered():
    from app.db_roles import APPEND_ONLY_TABLES

    assert {"attendance_corrections", "absence_alerts"} <= set(APPEND_ONLY_TABLES)
