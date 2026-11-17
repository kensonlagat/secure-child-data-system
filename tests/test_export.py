"""OTP-protected export (#65)."""

import csv
import io
from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.export import ExportRequest
from app.models.user import Role, User
from app.services import export_service
from class_helpers import put_in_class

PASSWORD = "Password#2026"


@pytest.fixture()
def sms(monkeypatch):
    sent = []

    def fake(phone, message):
        sent.append(message.split("code is ")[1].split(".")[0])

    monkeypatch.setattr("app.services.otp_service.send_sms", fake)
    return sent


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        admin_role = Role(name="administrator", institution_mode="both")
        teacher_role = Role(name="teacher", institution_mode="school")
        db.session.add_all([admin_role, teacher_role])
        db.session.flush()
        for email, role in (("admin@example.com", admin_role), ("admin2@example.com", admin_role),
                            ("teacher@example.com", teacher_role)):
            db.session.add(User(email=email, full_name=email, phone_number="+254700000001",
                                password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True))
        one = ChildRecord(full_name="=HYPERLINK(\"evil\")", date_of_birth=date(2014, 1, 1), institution_mode="school",
                          medical_notes="Asthma (marker-3xp)")
        two = ChildRecord(full_name="Plain Name", date_of_birth=date(2014, 2, 2), institution_mode="school")
        db.session.add_all([one, two])
        db.session.flush()
        c = put_in_class("Grade 6A", children=[one, two])
        db.session.commit()
        application.config.update(ONE=one.id, CLASS=c.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, email="admin@example.com", portal="school"):
    client = app.test_client()
    assert client.post("/login", data={"email": email, "password": PASSWORD, "portal": portal}).status_code == 302
    return client


def request_export(app, client, export_type="child_file", target=None, columns=("id", "full_name")):
    target = target if target is not None else app.config["ONE"]
    return client.post("/export/request", data={"export_type": export_type, "target_id": str(target),
                                                "columns": list(columns)})


def latest_request_id(app):
    with app.app_context():
        return ExportRequest.query.order_by(ExportRequest.id.desc()).first().id


def confirm(client, request_id, code):
    return client.post(f"/export/{request_id}/confirm", data={"otp_code": code})


def test_export_needs_a_verified_code_and_returns_csv(app, sms):
    admin = sign_in(app)
    request_export(app, admin, columns=("id", "full_name", "medical_notes"))
    response = confirm(admin, latest_request_id(app), sms[-1])
    assert response.status_code == 200 and response.mimetype == "text/csv"
    assert response.headers["Cache-Control"] == "no-store" and "attachment" in response.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[0] == ["id", "full_name", "medical_notes"] and rows[1][2] == "Asthma (marker-3xp)"


def test_wrong_code_exports_nothing(app, sms):
    admin = sign_in(app)
    request_export(app, admin)
    response = confirm(admin, latest_request_id(app), "000000" if sms[-1] != "000000" else "111111")
    assert response.status_code == 302 and response.mimetype != "text/csv"
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="export_otp_failed").count() == 1
        assert AuditLogEntry.query.filter_by(action="export_completed").count() == 0


def test_code_is_single_use(app, sms):
    admin = sign_in(app)
    request_export(app, admin)
    request_id, code = latest_request_id(app), sms[-1]
    assert confirm(admin, request_id, code).status_code == 200
    assert confirm(admin, request_id, code).status_code == 404  # request completed


def test_code_for_a_small_export_cannot_release_a_larger_one(app, sms):
    admin = sign_in(app)
    request_export(app, admin, columns=("id",))
    small_code = sms[-1]
    request_export(app, admin, "class_list", app.config["CLASS"], ("id", "full_name", "medical_notes"))
    large_id = latest_request_id(app)
    response = confirm(admin, large_id, small_code)
    assert response.mimetype != "text/csv"


def test_code_is_bound_to_the_requester(app, sms):
    request_export(app, sign_in(app))
    request_id, code = latest_request_id(app), sms[-1]
    assert confirm(sign_in(app, "admin2@example.com"), request_id, code).status_code == 404


def test_teachers_cannot_export(app, sms):
    teacher = sign_in(app, "teacher@example.com")
    assert teacher.get("/export/").status_code == 403
    assert request_export(app, teacher).status_code == 403
    assert sms == []


def test_columns_must_be_visible_to_the_requester(app, sms):
    request_export(app, sign_in(app), columns=("id", "password_hash"))
    with app.app_context():
        assert ExportRequest.query.count() == 0
    assert sms == []


def test_spreadsheet_formulas_are_escaped():
    for prefix in ("=", "+", "-", "@", "\t", "\r"):
        assert export_service._safe(prefix + "1+1").startswith("'")
    assert export_service._safe("Plain") == "Plain"


def test_formula_name_is_escaped_in_the_file(app, sms):
    admin = sign_in(app)
    request_export(app, admin)
    rows = list(csv.reader(io.StringIO(confirm(admin, latest_request_id(app), sms[-1]).get_data(as_text=True))))
    assert rows[1][1].startswith("'=")


def test_audit_records_counts_and_names_never_data(app, sms):
    admin = sign_in(app)
    request_export(app, admin, "class_list", app.config["CLASS"], ("id", "full_name", "medical_notes"))
    confirm(admin, latest_request_id(app), sms[-1])
    with app.app_context():
        done = AuditLogEntry.query.filter_by(action="export_completed").one()
        details = " ".join(r.details or "" for r in AuditLogEntry.query.all())
    assert "2 row(s), 3 column(s)" in done.details
    assert "marker-3xp" not in details and "Plain Name" not in details


def test_csv_is_never_written_to_disk(app, sms, monkeypatch, tmp_path):
    import builtins

    real_open = builtins.open
    written = []

    def tracking_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in ("w", "a", "x")):
            written.append(str(file))
        return real_open(file, mode, *args, **kwargs)

    admin = sign_in(app)
    request_export(app, admin)
    monkeypatch.setattr(builtins, "open", tracking_open)
    assert confirm(admin, latest_request_id(app), sms[-1]).status_code == 200
    assert written == []
