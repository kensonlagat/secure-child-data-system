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


@pytest.mark.parametrize("portal", ["school", "childrens_home"])
def test_login_with_portal_query_shows_locked_chip_and_hidden_field(app, portal):
    html = app.test_client().get(f"/login?portal={portal}").get_data(as_text=True)

    assert f'<input type="hidden" id="portal" name="portal" value="{portal}">' in html
    assert "<select" not in html
    assert "portal-chip" in html
    assert "Choose a different portal" in html
    # The form posts back to the same portal so a failed sign-in keeps the chip.
    assert f'action="/login?portal={portal}"' in html
    assert f'data-portal="{portal}"' in html
    assert 'name="csrf_token"' in html


@pytest.mark.parametrize("query", ["", "?portal=not-a-portal"])
def test_login_without_valid_portal_shows_dropdown(app, query):
    html = app.test_client().get(f"/login{query}").get_data(as_text=True)

    assert re.findall(r'<option value="(\w+)" selected', html) == ["school"]
    assert "portal-chip" not in html
    assert 'name="csrf_token"' in html


def test_children_home_label_is_display_only(app):
    html = app.test_client().get("/login?portal=childrens_home").get_data(as_text=True)

    assert "Children&#39;s Home" in html
    assert 'value="childrens_home"' in html
    assert "Childrens Home" not in html


@pytest.mark.parametrize("path", ["/forgot-password", "/reset-password"])
def test_password_pages_use_public_layout_when_signed_in(app, path):
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.config["TEST_TEACHER_ID"])
        session["_fresh"] = True

    html = client.get(path).get_data(as_text=True)

    assert 'class="public"' in html
    assert 'class="rail"' not in html
    assert "Test Teacher" not in html
