"""Search and pagination on the record lists (#32)."""

import re
from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.user import Role, User
from class_helpers import put_in_class

PASSWORD = "Password#2026"
SECRET_TERM = "Zawadi"


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        users = {}
        for role_name, mode in (("administrator", "both"), ("teacher", "school"), ("school_nurse", "school"),
                                ("legal_officer", "childrens_home")):
            role = Role(name=role_name, institution_mode=mode)
            db.session.add(role)
            db.session.flush()
            users[role_name] = User(email=f"{role_name}@example.com", full_name=role_name, phone_number="+254700000001",
                                    password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True)
            db.session.add(users[role_name])
        db.session.flush()
        mine = [ChildRecord(full_name=f"Child {i:02d}", date_of_birth=date(2014, 1, 1 + i % 28),
                            institution_mode="school") for i in range(30)]
        zawadi_mine = ChildRecord(full_name="Zawadi Otieno", date_of_birth=date(2013, 5, 5), institution_mode="school")
        zawadi_other = ChildRecord(full_name="Zawadi Kariuki", date_of_birth=date(2013, 6, 6), institution_mode="school")
        deleted = ChildRecord(full_name="Zawadi Deleted", date_of_birth=date(2013, 7, 7), institution_mode="school",
                              is_deleted=True)
        home = [ChildRecord(full_name=f"Home {i}", date_of_birth=date(2011, 1, 1), institution_mode="childrens_home",
                            legal_status=status) for i, status in enumerate(["in_state_care", "placed", "placed"])]
        db.session.add_all(mine + [zawadi_mine, zawadi_other, deleted] + home)
        db.session.flush()
        c6a = put_in_class("Grade 6A", children=mine + [zawadi_mine, deleted], teachers=[users["teacher"]])
        c7c = put_in_class("Grade 7C", children=[zawadi_other])
        db.session.commit()
        application.config.update(C6A=c6a.id, C7C=c7c.id, ZAWADI_MINE=zawadi_mine.id, ZAWADI_OTHER=zawadi_other.id,
                                  DELETED=deleted.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


PORTALS = {"administrator": "school", "teacher": "school", "school_nurse": "school", "legal_officer": "childrens_home"}


def sign_in(app, role_name, client=None):
    client = client or app.test_client()
    assert client.post("/login", data={"email": f"{role_name}@example.com", "password": PASSWORD,
                                       "portal": PORTALS[role_name]}).status_code == 302
    return client


def listing(client, path="/school/records", **params):
    response = client.get(path, query_string=params, headers={"Accept": "application/json"})
    return response.status_code, response.get_json()


def search(client, term, path="/school/records/search", **filters):
    return client.post(path, data={"name": term, **filters})


def audit_rows(app, action=None):
    with app.app_context():
        query = AuditLogEntry.query.order_by(AuditLogEntry.id)
        return [row for row in query if action is None or row.action == action]


# --- Scoping is preserved --------------------------------------------------------------


def test_teacher_searching_for_a_child_in_another_class_finds_nothing_from_it(app):
    teacher = sign_in(app, "teacher")
    search(teacher, SECRET_TERM)
    _, body = listing(teacher)
    assert [row["id"] for row in body["items"]] == [app.config["ZAWADI_MINE"]]
    assert body["total"] == 1


def test_deleted_records_never_appear(app):
    admin = sign_in(app, "administrator")
    search(admin, SECRET_TERM)
    _, body = listing(admin)
    ids = {row["id"] for row in body["items"]}
    assert app.config["DELETED"] not in ids and ids == {app.config["ZAWADI_MINE"], app.config["ZAWADI_OTHER"]}


def test_name_search_is_case_insensitive_and_partial(app):
    admin = sign_in(app, "administrator")
    search(admin, "zAwA")
    assert listing(admin)[1]["total"] == 2


# --- Filters only on fields the role can see -------------------------------------------


@pytest.mark.parametrize("role_name, path, params", [
    ("school_nurse", "/school/records", {"class_id": "1"}),       # nurse can't see the class
    ("teacher", "/school/records", {"legal_status": "placed"}),   # not a school field, and hidden
    ("administrator", "/school/records", {"legal_status": "placed"}),  # home-only filter
    ("legal_officer", "/home-mode/records", {"class_id": "1"}),   # school-only filter
    ("teacher", "/school/records", {"medical_notes": "asthma"}),  # not a filter at all
])
def test_filters_on_hidden_or_unknown_fields_are_refused_with_no_data(app, role_name, path, params):
    status, body = listing(sign_in(app, role_name), path, **params)
    assert status == 400
    assert "items" not in body
    assert len(audit_rows(app, "record_search_refused")) == 1


def test_admin_can_filter_by_class_and_birth_date(app):
    admin = sign_in(app, "administrator")
    assert listing(admin, class_id=app.config["C7C"])[1]["total"] == 1
    assert listing(admin, dob_from="2013-01-01", dob_to="2013-12-31")[1]["total"] == 2


def test_legal_officer_can_filter_by_legal_status(app):
    assert listing(sign_in(app, "legal_officer"), "/home-mode/records", legal_status="placed")[1]["total"] == 2


def test_name_search_is_refused_for_roles_that_cannot_see_names(app):
    # Every current role can see names; simulate one that can't by checking the service rule.
    from app.services.record_search import SearchError, set_name_term

    with app.test_request_context():
        with pytest.raises(SearchError):
            set_name_term("school", "anything", visible_fields=["id", "date_of_birth"])


# --- The search term never goes in a URL or the audit log --------------------------------


def test_search_posts_then_redirects_without_the_term(app):
    teacher = sign_in(app, "teacher")
    response = search(teacher, SECRET_TERM, class_id="")

    assert response.status_code == 302
    assert SECRET_TERM.lower() not in response.headers["Location"].lower()
    html = teacher.get(response.headers["Location"], headers={"Accept": "text/html"}).get_data(as_text=True)
    for href in re.findall(r'href="([^"]+)"', html):
        assert SECRET_TERM.lower() not in href.lower()


def test_search_is_audited_without_the_term(app):
    teacher = sign_in(app, "teacher")
    search(teacher, SECRET_TERM)
    listing(teacher)

    searches = audit_rows(app, "record_search")
    assert [row.details for row in searches] == ["Name search in school mode returned 1 result(s)"]
    assert "filters: name" in audit_rows(app, "view_records")[-1].details
    assert all(SECRET_TERM.lower() not in (row.details or "").lower() for row in audit_rows(app))


def test_non_sensitive_filters_travel_in_the_url(app):
    response = search(sign_in(app, "administrator"), "", class_id=str(1))
    assert "class_id=1" in response.headers["Location"]


def test_overlong_term_is_refused(app):
    admin = sign_in(app, "administrator")
    search(admin, "x" * 101)
    assert listing(admin)[1]["total"] == 32  # no term stored


# --- Clearing, signing out, separate modes ---------------------------------------------------


def test_clear_search_removes_the_term(app):
    admin = sign_in(app, "administrator")
    search(admin, SECRET_TERM)
    admin.post("/school/records/search/clear")
    assert listing(admin)[1]["total"] == 32


def test_sign_out_drops_the_term(app):
    client = sign_in(app, "administrator")
    search(client, SECRET_TERM)
    client.get("/logout")
    sign_in(app, "administrator", client)
    assert listing(client)[1]["total"] == 32


def test_signing_in_as_someone_else_starts_with_no_term(app):
    client = sign_in(app, "administrator")
    search(client, SECRET_TERM)
    sign_in(app, "teacher", client)  # same browser, no sign-out
    assert listing(client)[1]["total"] == 31


def test_terms_are_kept_per_mode(app):
    admin = sign_in(app, "administrator")
    search(admin, SECRET_TERM)
    assert listing(admin, "/home-mode/records")[1]["total"] == 3


# --- Pagination ------------------------------------------------------------------------------


def test_pages_and_totals(app):
    admin = sign_in(app, "administrator")
    status, first = listing(admin, per_page=10)
    _, second = listing(admin, per_page=10, page=2)
    assert status == 200
    assert (first["total"], first["page"], first["per_page"], len(first["items"])) == (32, 1, 10, 10)
    assert len(second["items"]) == 10 and {r["id"] for r in first["items"]}.isdisjoint({r["id"] for r in second["items"]})


def test_page_past_the_end_is_empty_but_keeps_the_total(app):
    _, body = listing(sign_in(app, "administrator"), per_page=10, page=9)
    assert body["items"] == [] and body["total"] == 32 and body["page"] == 9


@pytest.mark.parametrize("page, per_page, expected", [
    ("0", "10", (1, 10)), ("-3", "10", (1, 10)), ("abc", "10", (1, 10)),
    ("1", "7", (1, 25)), ("1", "1000", (1, 25)), ("1", "x", (1, 25)),
])
def test_bad_paging_values_fall_back_to_defaults(app, page, per_page, expected):
    _, body = listing(sign_in(app, "administrator"), page=page, per_page=per_page)
    assert (body["page"], body["per_page"]) == expected


def test_html_list_shows_search_and_paging_controls(app):
    html = sign_in(app, "administrator").get("/school/records", query_string={"per_page": 10},
                                             headers={"Accept": "text/html"}).get_data(as_text=True)
    assert 'action="/school/records/search"' in html
    assert "Page 1 of 4" in html and 'rel="next"' in html
    assert 'name="csrf_token"' in html


# --- CSRF switched on ---------------------------------------------------------------------------


def test_search_without_a_csrf_token_is_refused(app):
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()
    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").get_data(as_text=True)).group(1)
    client.post("/login", data={"email": "administrator@example.com", "password": PASSWORD, "portal": "school",
                                "csrf_token": token})

    client.post("/school/records/search", data={"name": SECRET_TERM})

    assert listing(client)[1]["total"] == 32  # nothing stored
