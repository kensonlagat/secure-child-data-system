"""Classes and enrolment (#48): scoping through the class link, enrolment rules, promotion,
create-record enrolment, staff class assignments, and the backfill migration."""

import importlib.util
from datetime import date
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass
from app.models.user import Role, User
from app.services import enrolment_service
from class_helpers import get_class, put_in_class

PASSWORD = "Password#2026"


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        roles = {name: Role(name=name, institution_mode=mode) for name, mode in (
            ("administrator", "both"), ("teacher", "school"), ("social_worker", "childrens_home"))}
        db.session.add_all(roles.values())
        db.session.flush()

        def user(key, role):
            account = User(email=f"{key}@example.com", full_name=f"Test {key}", phone_number="+254700000001",
                           password_hash=generate_password_hash(PASSWORD), role_id=roles[role].id, is_active=True)
            db.session.add(account)
            db.session.flush()
            return account

        admin, t6a, t6a_2, t7c, idle = (user("admin", "administrator"), user("t6a", "teacher"),
                                        user("t6a2", "teacher"), user("t7c", "teacher"), user("idle", "teacher"))
        children = {}
        for key in ("amina", "brian", "chebet", "dan"):
            children[key] = ChildRecord(full_name=f"Child {key}", date_of_birth=date(2014, 1, 1),
                                        institution_mode="school")
        children["home"] = ChildRecord(full_name="Home child", date_of_birth=date(2012, 1, 1),
                                       institution_mode="childrens_home")
        db.session.add_all(children.values())
        db.session.flush()
        c6a = put_in_class("Grade 6A", children=[children["amina"], children["brian"]], teachers=[t6a, t6a_2])
        c7c = put_in_class("Grade 7C", children=[children["chebet"]], teachers=[t7c])
        c8a = get_class("Grade 8A")
        db.session.commit()
        application.config["IDS"] = {
            "admin": admin.id, "t6a": t6a.id, "t6a2": t6a_2.id, "t7c": t7c.id, "idle": idle.id,
            **{k: v.id for k, v in children.items()},
            "c6a": c6a.id, "c7c": c7c.id, "c8a": c8a.id, "roles": {k: v.id for k, v in roles.items()},
        }
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def ids(app, key):
    return app.config["IDS"][key]


def sign_in(app, key, portal="school"):
    client = app.test_client()
    response = client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD, "portal": portal})
    assert response.status_code == 302
    return client


def visible_ids(app, key):
    rows = sign_in(app, key).get("/school/records", headers={"Accept": "application/json"}).get_json()
    return sorted(row["id"] for row in rows)


def audit(app, action):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=action).all()


def current_class_of(app, child_key):
    with app.app_context():
        enrolment = enrolment_service.current_enrolment(ids(app, child_key))
        return enrolment.class_id if enrolment else None


# --- Teacher scoping goes through the class link -------------------------------------


def test_teacher_sees_only_children_in_their_current_classes(app):
    assert visible_ids(app, "t6a") == sorted([ids(app, "amina"), ids(app, "brian")])
    assert visible_ids(app, "t7c") == [ids(app, "chebet")]


def test_both_teachers_of_a_shared_class_see_it(app):
    assert visible_ids(app, "t6a2") == visible_ids(app, "t6a")


def test_teacher_with_no_assignment_sees_nothing(app):
    assert visible_ids(app, "idle") == []


def test_legacy_free_text_class_grants_nothing(app):
    with app.app_context():
        db.session.get(User, ids(app, "idle")).assigned_class = "Grade 6A"
        db.session.get(ChildRecord, ids(app, "dan")).class_assigned = "Grade 6A"
        db.session.commit()
    assert visible_ids(app, "idle") == []


def test_moved_child_leaves_the_old_teachers_view(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/records/{ids(app, 'amina')}/class", data={"class_id": ids(app, "c7c")})

    assert ids(app, "amina") not in visible_ids(app, "t6a")
    assert ids(app, "amina") in visible_ids(app, "t7c")
    assert [row.details for row in audit(app, "child_moved")] == [
        f"Moved from class_id={ids(app, 'c6a')} to class_id={ids(app, 'c7c')}"]


def test_archived_class_grants_no_teacher_access(app):
    sign_in(app, "admin").post(f"/admin/classes/{ids(app, 'c6a')}/archive")

    assert visible_ids(app, "t6a") == []
    assert len(audit(app, "class_archived")) == 1
    sign_in(app, "admin").post(f"/admin/classes/{ids(app, 'c6a')}/reactivate")
    assert len(visible_ids(app, "t6a")) == 2


def test_unassigned_teacher_loses_access(app):
    sign_in(app, "admin").post(f"/admin/classes/{ids(app, 'c6a')}/teachers/{ids(app, 't6a')}/remove")

    assert visible_ids(app, "t6a") == []
    assert len(visible_ids(app, "t6a2")) == 2
    assert len(audit(app, "class_teacher_unassigned")) == 1


def test_deleted_records_stay_invisible_even_when_enrolled(app):
    with app.app_context():
        db.session.get(ChildRecord, ids(app, "amina")).is_deleted = True
        db.session.commit()
    assert visible_ids(app, "t6a") == [ids(app, "brian")]


def test_teacher_list_shows_the_class_label(app):
    rows = sign_in(app, "t6a").get("/school/records", headers={"Accept": "application/json"}).get_json()
    assert {row["class_label"] for row in rows} == {"Grade 6A"}
    assert all("class_assigned" not in row for row in rows)


def test_class_management_is_admin_only(app):
    teacher = sign_in(app, "t6a")
    assert teacher.get("/admin/classes").status_code == 403
    assert teacher.post(f"/admin/classes/{ids(app, 'c8a')}/enrol",
                        data={"child_record_id": ids(app, "dan")}).status_code == 403
    assert current_class_of(app, "dan") is None


# --- Enrolment rules -----------------------------------------------------------------


def test_one_current_enrolment_per_child_is_enforced_by_the_application(app):
    with app.app_context():
        admin = db.session.get(User, ids(app, "admin"))
        child = db.session.get(ChildRecord, ids(app, "amina"))
        with pytest.raises(enrolment_service.EnrolmentError, match="already has a current class"):
            enrolment_service.enrol_child(admin, child, db.session.get(SchoolClass, ids(app, "c8a")))
        db.session.rollback()
        assert Enrolment.query.filter_by(child_record_id=child.id, ended_on=None).count() == 1


def test_enrolling_an_already_enrolled_child_through_the_page_is_refused(app):
    response = sign_in(app, "admin").post(f"/admin/classes/{ids(app, 'c8a')}/enrol",
                                          data={"child_record_id": ids(app, "amina")})
    assert response.status_code == 302
    assert current_class_of(app, "amina") == ids(app, "c6a")
    assert audit(app, "child_enrolled") == []


def test_children_home_records_cannot_be_enrolled(app):
    response = sign_in(app, "admin").post(f"/admin/classes/{ids(app, 'c8a')}/enrol",
                                          data={"child_record_id": ids(app, "home")})
    assert response.status_code == 404
    assert current_class_of(app, "home") is None


def test_archived_classes_cannot_take_new_enrolments(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/classes/{ids(app, 'c8a')}/archive")
    admin.post(f"/admin/classes/{ids(app, 'c8a')}/enrol", data={"child_record_id": ids(app, "dan")})
    assert current_class_of(app, "dan") is None


def test_removing_a_child_closes_the_enrolment_and_keeps_history(app):
    sign_in(app, "admin").post(f"/admin/records/{ids(app, 'amina')}/class/remove")

    assert current_class_of(app, "amina") is None
    with app.app_context():
        closed = Enrolment.query.filter_by(child_record_id=ids(app, "amina")).one()
        assert closed.ended_on is not None and closed.end_reason == "left"
    assert len(audit(app, "child_left_class")) == 1


@pytest.mark.parametrize("role_key", ["admin", "t6a"])
def test_class_assigned_cannot_be_patched_by_any_role(app, role_key):
    response = sign_in(app, role_key).patch(f"/school/records/{ids(app, 'amina')}", json={"class_assigned": "Grade 8A"})
    assert response.status_code == 400
    assert current_class_of(app, "amina") == ids(app, "c6a")


# --- Year-end promotion ----------------------------------------------------------------


def test_promotion_moves_exactly_the_current_enrolments_with_one_audit_row(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/records/{ids(app, 'brian')}/class", data={"class_id": ids(app, "c7c")})  # moved out first

    admin.post(f"/admin/classes/{ids(app, 'c6a')}/promote", data={"target_class_id": ids(app, "c8a")})

    assert current_class_of(app, "amina") == ids(app, "c8a")
    assert current_class_of(app, "brian") == ids(app, "c7c")  # no longer in 6A, so not promoted
    assert [row.details for row in audit(app, "class_promoted")] == [
        f"Promoted 1 children from class_id={ids(app, 'c6a')} to class_id={ids(app, 'c8a')}"]


def test_promotion_failure_rolls_everything_back(app, monkeypatch):
    real_open = enrolment_service._open
    calls = []

    def fail_on_second(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("database went away")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(enrolment_service, "_open", fail_on_second)
    with app.app_context():
        admin = db.session.get(User, ids(app, "admin"))
        with pytest.raises(RuntimeError):
            enrolment_service.promote_class(admin, db.session.get(SchoolClass, ids(app, "c6a")),
                                            db.session.get(SchoolClass, ids(app, "c8a")))
    assert current_class_of(app, "amina") == ids(app, "c6a")
    assert current_class_of(app, "brian") == ids(app, "c6a")
    assert audit(app, "class_promoted") == []


def test_promotion_into_an_archived_class_is_refused(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/classes/{ids(app, 'c8a')}/archive")
    admin.post(f"/admin/classes/{ids(app, 'c6a')}/promote", data={"target_class_id": ids(app, "c8a")})
    assert current_class_of(app, "amina") == ids(app, "c6a")


def test_promotion_closes_deleted_records_without_carrying_them_forward(app):
    with app.app_context():
        db.session.get(ChildRecord, ids(app, "amina")).is_deleted = True
        db.session.commit()
    sign_in(app, "admin").post(f"/admin/classes/{ids(app, 'c6a')}/promote", data={"target_class_id": ids(app, "c8a")})

    assert current_class_of(app, "amina") is None
    assert current_class_of(app, "brian") == ids(app, "c8a")


# --- Create-record enrols in the same transaction ---------------------------------------


def new_record(app, **extra):
    return {"full_name": "New Child", "date_of_birth": "2015-02-02", "institution_mode": "school", **extra}


def record_count(app):
    with app.app_context():
        return ChildRecord.query.count()


def test_create_record_enrols_through_the_class_link(app):
    response = sign_in(app, "admin").post("/admin/records", json=new_record(app, class_id=ids(app, "c8a")))

    assert response.status_code == 201
    new_id = response.get_json()["id"]
    with app.app_context():
        assert enrolment_service.current_enrolment(new_id).class_id == ids(app, "c8a")
    assert [row.target_record_id for row in audit(app, "child_enrolled")] == [new_id]


def test_create_record_with_an_archived_class_creates_nothing(app):
    before = record_count(app)
    admin = sign_in(app, "admin")
    admin.post(f"/admin/classes/{ids(app, 'c8a')}/archive")

    response = admin.post("/admin/records", json=new_record(app, class_id=ids(app, "c8a")))

    assert response.status_code == 400
    assert record_count(app) == before


def test_create_record_rolls_back_when_enrolment_fails(app, monkeypatch):
    def broken(*args, **kwargs):
        raise enrolment_service.EnrolmentError("Choose an active class.")

    monkeypatch.setattr("app.blueprints.admin.routes.enrol_child", broken)
    before = record_count(app)

    response = sign_in(app, "admin").post("/admin/records", json=new_record(app, class_id=ids(app, "c8a")))

    assert response.status_code == 400
    assert record_count(app) == before
    assert audit(app, "create_record") == []


def test_create_record_refuses_the_old_free_text_class(app):
    before = record_count(app)
    response = sign_in(app, "admin").post("/admin/records", json=new_record(app, class_assigned="Grade 6A"))
    assert response.status_code == 400
    assert record_count(app) == before


def test_create_record_form_lists_active_classes_only(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/classes/{ids(app, 'c8a')}/archive")
    html = admin.get("/admin/records/new").get_data(as_text=True)
    assert f'value="{ids(app, "c6a")}"' in html
    assert f'value="{ids(app, "c8a")}"' not in html


# --- Classes themselves -------------------------------------------------------------------


def test_create_class_is_audited_and_duplicates_are_refused(app):
    admin = sign_in(app, "admin")
    admin.post("/admin/classes", data={"name": "Grade 5", "stream": "b", "academic_year": "2026"})
    admin.post("/admin/classes", data={"name": "Grade 5", "stream": "B", "academic_year": "2026"})

    with app.app_context():
        assert SchoolClass.query.filter_by(name="Grade 5", stream="B", academic_year=2026).count() == 1
    assert len(audit(app, "class_created")) == 1


def test_audit_rows_never_contain_child_names(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/records/{ids(app, 'amina')}/class", data={"class_id": ids(app, "c7c")})
    admin.post(f"/admin/classes/{ids(app, 'c7c')}/promote", data={"target_class_id": ids(app, "c8a")})
    admin.post("/admin/records", json=new_record(app, class_id=ids(app, "c8a")))

    with app.app_context():
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    for name in ("Child amina", "Child chebet", "New Child"):
        assert name not in details


# --- Staff form: class assignments replace free text ------------------------------------


def staff_form(app, **extra):
    return {"full_name": "New Teacher", "email": "newteacher@example.com", "phone_number": "+254711111111",
            "role_id": str(ids(app, "roles")["teacher"]), **extra}


def test_new_teacher_gets_class_assignments_and_audits(app, monkeypatch):
    monkeypatch.setattr("app.services.otp_service.send_sms", lambda *a, **k: None)
    response = sign_in(app, "admin").post("/admin/users", data=staff_form(app, class_ids=[str(ids(app, "c8a"))]))

    assert response.status_code == 302
    with app.app_context():
        teacher = User.query.filter_by(email="newteacher@example.com").one()
        assert enrolment_service.current_class_ids_for_teacher(teacher.id) == [ids(app, "c8a")]
        assert teacher.assigned_class is None
    assert len(audit(app, "class_teacher_assigned")) == 1


def test_editing_a_teacher_changes_assignments_and_role_change_ends_them(app):
    admin = sign_in(app, "admin")
    form = {"full_name": "Test t6a", "phone_number": "+254700000001", "role_id": str(ids(app, "roles")["teacher"])}

    admin.post(f"/admin/users/{ids(app, 't6a')}/edit", data={**form, "class_ids": [str(ids(app, "c7c"))]})
    assert visible_ids(app, "t6a") == [ids(app, "chebet")]

    admin.post(f"/admin/users/{ids(app, 't6a')}/edit",
               data={**form, "role_id": str(ids(app, "roles")["social_worker"]), "class_ids": [str(ids(app, "c7c"))]})
    with app.app_context():
        assert enrolment_service.current_class_ids_for_teacher(ids(app, "t6a")) == []


def test_staff_form_refuses_an_archived_class(app):
    admin = sign_in(app, "admin")
    admin.post(f"/admin/classes/{ids(app, 'c8a')}/archive")
    response = admin.post("/admin/users", data=staff_form(app, class_ids=[str(ids(app, "c8a"))]))

    assert response.status_code == 400
    with app.app_context():
        assert User.query.filter_by(email="newteacher@example.com").first() is None


def test_staff_form_has_class_checkboxes_not_free_text(app):
    html = sign_in(app, "admin").get("/admin/users/new").get_data(as_text=True)
    assert 'name="class_ids"' in html
    assert 'name="assigned_class"' not in html


# --- Backfill migration -------------------------------------------------------------------

MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "e3a8c6b2f415_add_classes_and_enrolments.py"


def test_backfill_maps_every_legacy_value(monkeypatch):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        for table in ("enrolments", "class_teacher_assignments", "school_classes"):
            db.metadata.tables[table].drop(db.engine)  # the state before this migration
        teacher_role = Role(name="teacher", institution_mode="school")
        db.session.add(teacher_role)
        db.session.flush()
        db.session.add_all([
            User(email="a@example.com", full_name="A", phone_number="+254700000001", password_hash="x",
                 role_id=teacher_role.id, assigned_class="Grade 6A"),
            User(email="b@example.com", full_name="B", phone_number="+254700000002", password_hash="x",
                 role_id=teacher_role.id, assigned_class="Grade 6A"),
            User(email="c@example.com", full_name="C", phone_number="+254700000003", password_hash="x",
                 role_id=teacher_role.id, assigned_class="Grade 5B"),
        ])
        for label, deleted in (("Grade 6A", False), ("Grade 6A", True), ("Nursery", False), (None, False)):
            db.session.add(ChildRecord(full_name="X", date_of_birth=date(2014, 1, 1), institution_mode="school",
                                       class_assigned=label, is_deleted=deleted))
        db.session.add(ChildRecord(full_name="H", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home"))
        db.session.commit()

        spec = importlib.util.spec_from_file_location("classes_migration", MIGRATION)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with db.engine.begin() as connection:
            module.op = Operations(MigrationContext.configure(connection))
            module.upgrade()

        labels = {(c.name, c.stream, c.academic_year) for c in SchoolClass.query.all()}
        assert labels == {("Grade 6", "A", 2026), ("Grade 5", "B", 2026), ("Nursery", "", 2026)}
        assert Enrolment.query.count() == 3  # both Grade 6A records (deleted included) and Nursery
        assert {e.reason for e in Enrolment.query.all()} == {"migrated"}
        assert ClassTeacherAssignment.query.count() == 3
        six_a = SchoolClass.query.filter_by(name="Grade 6", stream="A").one()
        assert ClassTeacherAssignment.query.filter_by(class_id=six_a.id).count() == 2
        db.session.remove()
        db.drop_all()


def test_class_list_count_excludes_deleted_records(app):
    with app.app_context():
        db.session.get(ChildRecord, ids(app, "amina")).is_deleted = True
        db.session.commit()
    html = sign_in(app, "admin").get("/admin/classes").get_data(as_text=True)
    row = html.split("Grade 6A</td>", 1)[1].split("</tr>", 1)[0]
    assert '<td class="mono">1</td>' in row


def test_class_pages_render_for_admin(app):
    admin = sign_in(app, "admin")
    detail = admin.get(f"/admin/classes/{ids(app, 'c6a')}")
    html = detail.get_data(as_text=True)
    assert detail.status_code == 200
    assert "Test t6a" in html and "Child amina" in html and 'name="csrf_token"' in html
    assert "Year-end promotion" in html
    assert admin.get("/admin/classes").status_code == 200
    assert admin.get(f"/admin/users/{ids(app, 't6a')}/edit").status_code == 200
    assert admin.get("/admin/classes/99999").status_code == 404
