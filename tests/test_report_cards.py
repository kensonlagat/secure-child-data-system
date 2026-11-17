"""Term report cards (#70): teachers enter marks only for their own classes, through a field
allowlist; archived children are excluded; published reports are read-only."""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.report_card import LEARNING_AREA_KEYS, ReportCard, ReportCardEntry
from app.models.school_class import SchoolClass
from app.models.user import Role, User
from app.services import report_card_service
from app.services.attendance_service import class_children
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "teacher_b": "school", "principal": "school",
         "school_nurse": "school", "social_worker": "childrens_home"}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}
SECRET_COMMENT = "Struggles at home since the move"
YEAR, TERM = 2026, 1


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users, roles = {}, {}
        for key, mode in ROLES.items():
            role_name = "teacher" if key.startswith("teacher") else key
            if role_name not in roles:
                roles[role_name] = Role(name=role_name, institution_mode=mode)
                db.session.add(roles[role_name])
                db.session.flush()
            users[key] = User(email=f"{key}@example.com", full_name=key, phone_number="+254700000001",
                              password_hash=generate_password_hash(PASSWORD), role_id=roles[role_name].id,
                              is_active=True)
            db.session.add(users[key])
        db.session.flush()
        amani = ChildRecord(full_name="Amani Pupil", date_of_birth=date(2014, 1, 1), institution_mode="school")
        baraka = ChildRecord(full_name="Baraka Pupil", date_of_birth=date(2014, 1, 1), institution_mode="school")
        archived = ChildRecord(full_name="Gone Pupil", date_of_birth=date(2014, 1, 1), institution_mode="school")
        other = ChildRecord(full_name="Other Class Pupil", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([amani, baraka, archived, other])
        db.session.flush()
        c6a = put_in_class("Grade 6A", children=[amani, baraka, archived], teachers=[users["teacher"]])
        c7b = put_in_class("Grade 7B", children=[other], teachers=[users["teacher_b"]])
        archived.is_archived = True
        db.session.commit()
        application.config.update(AMANI=amani.id, BARAKA=baraka.id, ARCHIVED=archived.id, OTHER=other.id,
                                  C6A=c6a.id, C7B=c7b.id, TEACHER=users["teacher"].id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    role = "teacher" if key.startswith("teacher") else key
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLES[key]]}).status_code == 302, role
    return client


def full_form(level="ME", **extra):
    form = {f"level_{area}": level for area in LEARNING_AREA_KEYS}
    form.update({"year": YEAR, "term": TERM, "comment_english": SECRET_COMMENT, "teacher_comment": "Good term"})
    form.update(extra)
    return form


def entry_url(app, child="AMANI", klass="C6A"):
    return f"/reports/classes/{app.config[klass]}/children/{app.config[child]}"


def card_for(app, child="AMANI"):
    return ReportCard.query.filter_by(child_record_id=app.config[child], academic_year=YEAR, term=TERM).first()


# --- Who may enter marks --------------------------------------------------------------------------


def test_class_teacher_saves_a_draft(app):
    client = sign_in(app, "teacher")
    response = client.post(entry_url(app), data=full_form())
    assert response.status_code == 302
    with app.app_context():
        card = card_for(app)
        assert card.status == "draft" and len(card.entries) == len(LEARNING_AREA_KEYS)
        assert card.class_id == app.config["C6A"]


@pytest.mark.parametrize("key", ["teacher_b", "administrator", "principal", "school_nurse"])
def test_nobody_else_can_enter_marks_for_the_class(app, key):
    client = sign_in(app, key)
    assert client.get(entry_url(app), query_string={"year": YEAR, "term": TERM}).status_code == 404
    assert client.post(entry_url(app), data=full_form()).status_code == 404
    with app.app_context():
        assert card_for(app) is None


def test_a_teacher_cannot_enter_marks_for_another_classs_child_through_their_own_class_url(app):
    client = sign_in(app, "teacher")
    assert client.post(entry_url(app, child="OTHER", klass="C6A"), data=full_form()).status_code == 404
    assert client.post(entry_url(app, child="OTHER", klass="C7B"), data=full_form()).status_code == 404
    with app.app_context():
        assert card_for(app, "OTHER") is None
        assert AuditLogEntry.query.filter_by(action="access_denied").count() >= 1


def test_social_worker_cannot_open_report_cards(app):
    client = sign_in(app, "social_worker")
    assert client.get("/reports/").status_code == 403
    assert client.get(f"/reports/classes/{app.config['C6A']}").status_code == 404


# --- Field allowlist --------------------------------------------------------------------------------


def test_only_allowlisted_fields_are_read_from_the_form(app):
    client = sign_in(app, "teacher")
    client.post(entry_url(app), data=full_form(status="published", class_id=app.config["C7B"],
                                               child_record_id=app.config["OTHER"], created_by=999,
                                               level_not_an_area="EE", published_by=1))
    with app.app_context():
        card = card_for(app)
        assert card.status == "draft"
        assert card.class_id == app.config["C6A"] and card.published_by is None
        assert card.created_by == app.config["TEACHER"]
        assert {e.learning_area for e in card.entries} == set(LEARNING_AREA_KEYS)
        assert card_for(app, "OTHER") is None


@pytest.mark.parametrize("extra", [{"level_english": "A+"}, {"level_english": "ee"},
                                   {"teacher_comment": "x" * 1001}, {"comment_english": "y" * 301}])
def test_bad_values_are_refused_and_nothing_is_saved(app, extra):
    client = sign_in(app, "teacher")
    assert client.post(entry_url(app), data=full_form(**extra)).status_code == 302
    with app.app_context():
        assert card_for(app) is None
        assert AuditLogEntry.query.filter_by(action="report_card_save_refused").count() == 1


@pytest.mark.parametrize("year, term", [(1999, 1), (2026, 4), ("x", 1)])
def test_bad_year_or_term_is_refused(app, year, term):
    client = sign_in(app, "teacher")
    assert client.post(entry_url(app), data=full_form(year=year, term=term)).status_code == 400


# --- Archived children ------------------------------------------------------------------------------


def test_archived_children_are_excluded_everywhere(app):
    with app.app_context():
        children = class_children(db.session.get(SchoolClass, app.config["C6A"]))
        assert all(child.id != app.config["ARCHIVED"] for child in children)
    teacher = sign_in(app, "teacher")
    page = teacher.get(f"/reports/classes/{app.config['C6A']}", query_string={"year": YEAR, "term": TERM})
    assert "Gone Pupil" not in page.get_data(as_text=True)
    assert teacher.post(entry_url(app, child="ARCHIVED"), data=full_form()).status_code == 404


def test_cards_of_a_child_archived_later_can_no_longer_be_read(app):
    teacher = sign_in(app, "teacher")
    teacher.post(entry_url(app), data=full_form(publish="1"))
    with app.app_context():
        card_id = card_for(app).id
        db.session.get(ChildRecord, app.config["AMANI"]).is_archived = True
        db.session.commit()
    for key in ("teacher", "principal", "administrator"):
        assert sign_in(app, key).get(f"/reports/cards/{card_id}").status_code == 404


# --- Publishing makes marks read-only -------------------------------------------------------------


def test_publishing_needs_every_learning_area(app):
    client = sign_in(app, "teacher")
    form = full_form(publish="1")
    form.pop("level_mathematics")
    client.post(entry_url(app), data=form)
    with app.app_context():
        assert card_for(app).status == "draft"


def test_published_report_cannot_be_changed(app):
    client = sign_in(app, "teacher")
    response = client.post(entry_url(app), data=full_form(publish="1"))
    assert response.status_code == 302 and "/reports/cards/" in response.headers["Location"]
    with app.app_context():
        card = card_for(app)
        assert card.status == "published" and card.published_by == app.config["TEACHER"]
        before = {(e.learning_area, e.level, e.comment) for e in card.entries}
    client.post(entry_url(app), data=full_form(level="BE", teacher_comment="changed"))
    edit = client.get(entry_url(app), query_string={"year": YEAR, "term": TERM})
    assert edit.status_code == 302  # the edit page sends you to the read-only view
    with app.app_context():
        card = card_for(app)
        assert {(e.learning_area, e.level, e.comment) for e in card.entries} == before
        assert card.teacher_comment == "Good term"
        assert AuditLogEntry.query.filter_by(action="report_card_save_refused").count() == 1
        with pytest.raises(report_card_service.ReportCardError, match="published"):
            report_card_service.save_draft(db.session.get(User, app.config["TEACHER"]),
                                           db.session.get(SchoolClass, app.config["C6A"]),
                                           db.session.get(ChildRecord, app.config["AMANI"]), YEAR, TERM, full_form())
        with pytest.raises(report_card_service.ReportCardError, match="already published"):
            report_card_service.publish(db.session.get(User, app.config["TEACHER"]), card)


# --- Reading ----------------------------------------------------------------------------------------


def test_class_teacher_principal_and_admin_read_but_another_teacher_does_not(app):
    sign_in(app, "teacher").post(entry_url(app), data=full_form(publish="1"))
    with app.app_context():
        card_id = card_for(app).id
    for key in ("teacher", "principal", "administrator"):
        response = sign_in(app, key).get(f"/reports/cards/{card_id}")
        assert response.status_code == 200, key
        assert SECRET_COMMENT in response.get_data(as_text=True)
    for key in ("teacher_b", "school_nurse", "social_worker"):
        assert sign_in(app, key).get(f"/reports/cards/{card_id}").status_code == 404, key
    assert sign_in(app, "teacher_b").get(f"/reports/classes/{app.config['C6A']}").status_code == 404


def test_viewing_is_audited_and_bounded(app):
    client = sign_in(app, "teacher")
    client.post(entry_url(app), data=full_form(publish="1"))
    with app.app_context():
        card_id = card_for(app).id
    for _ in range(5):
        client.get(f"/reports/cards/{card_id}")
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="report_card_viewed").count() == 1


# --- Nothing sensitive at rest or in the audit log -----------------------------------------------


def test_comments_are_encrypted_at_rest_and_never_logged(app):
    sign_in(app, "teacher").post(entry_url(app), data=full_form())
    with app.app_context():
        raw = db.session.execute(text("SELECT comment FROM report_card_entries WHERE learning_area = 'english'")).scalar()
        assert SECRET_COMMENT.encode() not in bytes(raw)
        raw_teacher = db.session.execute(text("SELECT teacher_comment FROM report_cards")).scalar()
        assert b"Good term" not in bytes(raw_teacher)
        for row in AuditLogEntry.query.all():
            assert SECRET_COMMENT not in (row.details or "") and "Good term" not in (row.details or "")
            assert " ME" not in (row.details or "")


def test_entries_are_never_deleted_by_a_blank_level(app):
    client = sign_in(app, "teacher")
    client.post(entry_url(app), data=full_form())
    form = full_form()
    form["level_english"] = ""
    client.post(entry_url(app), data=form)
    with app.app_context():
        assert ReportCardEntry.query.filter_by(learning_area="english").one().level == "ME"
