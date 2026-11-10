"""The public landing page at / and the portal pre-selection on /login."""

import re

import pytest
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models.user import Role, User


@pytest.fixture()
def app():
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        role = Role(name="teacher", institution_mode="school")
        db.session.add(role)
        db.session.flush()
        teacher = User(
            email="teacher@example.com",
            full_name="Test Teacher",
            phone_number="+254700000001",
            password_hash=generate_password_hash("Teacher#2026"),
            role_id=role.id,
            is_active=True,
        )
        db.session.add(teacher)
        db.session.commit()
        application.config["TEST_TEACHER_ID"] = teacher.id
    yield application
    with application.app_context():
        db.drop_all()


def test_signed_out_root_shows_landing_with_both_portal_doors(app):
    response = app.test_client().get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'href="/login?portal=school"' in html
    assert 'href="/login?portal=childrens_home"' in html
    assert "Two-person approval" in html


def test_signed_in_root_redirects_to_role_landing_page(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.config["TEST_TEACHER_ID"])
        session["_fresh"] = True

    response = client.get("/")

    assert response.status_code == 302
    assert response.location.endswith("/school/records")


@pytest.mark.parametrize(
    "query, expected",
    [
        ("?portal=childrens_home", "childrens_home"),
        ("?portal=school", "school"),
        ("?portal=not-a-portal", "school"),
        ("", "school"),
    ],
)
def test_login_preselects_portal_from_query_string(app, query, expected):
    html = app.test_client().get(f"/login{query}").get_data(as_text=True)

    assert re.findall(r'<option value="(\w+)" selected', html) == [expected]
    assert 'name="csrf_token"' in html
