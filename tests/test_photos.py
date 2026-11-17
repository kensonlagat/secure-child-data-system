"""Child photos (#87): record page only, never in lists, only with photo consent."""

import io
from datetime import date

import pytest
from cryptography.fernet import Fernet
from PIL import Image
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.photo import ChildPhoto
from app.models.user import Role, User
from app.services import consent_service
from class_helpers import put_in_class

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school"}


def photo_bytes(exif=True):
    image = Image.new("RGB", (30, 30), "blue")
    out = io.BytesIO()
    extra = {}
    if exif:
        data = Image.Exif()
        data[0x010F] = "SecretCameraMaker"
        extra["exif"] = data.tobytes()
    image.save(out, format="JPEG", **extra)
    return out.getvalue()


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    application.config["FIELD_ENCRYPTION_KEY"] = BaseConfig.FIELD_ENCRYPTION_KEY
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
        child = ChildRecord(full_name="Photo Child", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add(child)
        db.session.flush()
        put_in_class("Grade 6A", children=[child], teachers=[users["teacher"]])
        db.session.commit()
        application.config.update(CHILD=child.id, ADMIN=users["administrator"].id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": "school"}).status_code == 302
    return client


def upload(app, client, data=None):
    return client.post(f"/photos/records/{app.config['CHILD']}", content_type="multipart/form-data",
                       data={"photo": (io.BytesIO(data or photo_bytes()), "me.jpg")})


def set_consent(app, status):
    with app.app_context():
        admin = db.session.get(User, app.config["ADMIN"])
        child = db.session.get(ChildRecord, app.config["CHILD"])
        consent_service.record(admin, child, "photo", status, date.today(), "Guardian Name")


def test_photo_is_hidden_without_consent(app):
    upload(app, sign_in(app, "administrator"))
    teacher = sign_in(app, "teacher")
    assert teacher.get(f"/photos/records/{app.config['CHILD']}").status_code == 404
    page = teacher.get(f"/school/records/{app.config['CHILD']}/edit").get_data(as_text=True)
    assert "/photos/records/" not in page


def test_photo_shows_on_the_record_page_with_consent(app):
    upload(app, sign_in(app, "administrator"))
    set_consent(app, "given")
    teacher = sign_in(app, "teacher")
    response = teacher.get(f"/photos/records/{app.config['CHILD']}")
    assert response.status_code == 200 and response.mimetype == "image/jpeg"
    assert response.headers["X-Content-Type-Options"] == "nosniff" and response.headers["Cache-Control"] == "no-store"
    assert f"/photos/records/{app.config['CHILD']}" in teacher.get(f"/school/records/{app.config['CHILD']}/edit").get_data(as_text=True)


def test_withdrawn_consent_hides_the_photo_again(app):
    upload(app, sign_in(app, "administrator"))
    set_consent(app, "given")
    set_consent(app, "withdrawn")
    assert sign_in(app, "teacher").get(f"/photos/records/{app.config['CHILD']}").status_code == 404


def test_photo_never_appears_in_lists(app):
    upload(app, sign_in(app, "administrator"))
    set_consent(app, "given")
    html = sign_in(app, "teacher").get("/school/records", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert "/photos/" not in html


def test_roles_outside_the_list_cannot_see_it(app):
    upload(app, sign_in(app, "administrator"))
    set_consent(app, "given")
    assert sign_in(app, "principal").get(f"/photos/records/{app.config['CHILD']}").status_code == 404


def test_only_administrators_upload(app):
    assert upload(app, sign_in(app, "teacher")).status_code == 403
    with app.app_context():
        assert ChildPhoto.query.count() == 0


def test_photo_is_reencoded_encrypted_and_exif_free(app):
    upload(app, sign_in(app, "administrator"))
    set_consent(app, "given")
    data = sign_in(app, "teacher").get(f"/photos/records/{app.config['CHILD']}").data
    assert b"SecretCameraMaker" not in data
    with app.app_context():
        stored = bytes(db.session.execute(text("SELECT ciphertext FROM child_photos")).scalar())
    assert not stored.startswith(b"\xff\xd8\xff")


def test_non_images_are_refused(app):
    upload(app, sign_in(app, "administrator"), data=b"%PDF-1.4 not a photo")
    with app.app_context():
        assert ChildPhoto.query.count() == 0


def test_views_are_audited_but_bounded(app):
    upload(app, sign_in(app, "administrator"))
    set_consent(app, "given")
    teacher = sign_in(app, "teacher")
    for _ in range(5):
        teacher.get(f"/photos/records/{app.config['CHILD']}")
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="child_photo_viewed").count() == 1


def test_child_photos_are_append_only():
    from app.db_roles import APPEND_ONLY_TABLES

    assert "child_photos" in APPEND_ONLY_TABLES
