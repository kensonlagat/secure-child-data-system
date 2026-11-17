"""Encrypted document storage (#66)."""

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
from app.models.document import Document, DocumentBlob
from app.models.user import Role, User
from app.services import document_service

PASSWORD = "Password#2026"
ROLES = {"administrator": "both", "social_worker": "childrens_home", "legal_officer": "childrens_home",
         "school_nurse": "school", "teacher": "school", "home_manager": "childrens_home"}
PORTAL = {"both": "childrens_home", "school": "school", "childrens_home": "childrens_home"}
PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer <<>>\n%%EOF marker-d0c"


def png_with_exif():
    image = Image.new("RGB", (20, 20), "red")
    exif = Image.Exif()
    exif[0x010F] = "SecretCameraMaker"
    out = io.BytesIO()
    image.save(out, format="PNG", exif=exif.tobytes())
    return out.getvalue()


@pytest.fixture()
def otp_codes(monkeypatch):
    codes = []
    monkeypatch.setattr("app.services.otp_service.send_sms",
                        lambda phone, message: codes.append(message.split("code is ")[1].split(".")[0]))
    return codes


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
        home = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home",
                           caseload_worker_id=users["social_worker"].id)
        school = ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([home, school])
        db.session.commit()
        application.config.update(HOME=home.id, SCHOOL=school.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key, portal=None):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": portal or PORTAL[ROLES[key]]}).status_code == 302
    return client


def upload(app, client, key="HOME", document_type="court_order", data=PDF, name="Order for Home Child.pdf"):
    return client.post(f"/documents/records/{app.config[key]}", content_type="multipart/form-data",
                       data={"document_type": document_type, "file": (io.BytesIO(data), name)})


def only_document(app):
    with app.app_context():
        document = Document.query.one()
        db.session.expunge(document)
        return document


def test_legal_officer_uploads_and_social_worker_downloads(app):
    upload(app, sign_in(app, "legal_officer"))
    document = only_document(app)
    response = sign_in(app, "social_worker").get(f"/documents/{document.id}")
    assert response.status_code == 200 and response.data == PDF
    assert response.headers["Content-Disposition"] == f'attachment; filename="document-{document.id}.pdf"'
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store" and response.headers["Content-Security-Policy"] == "sandbox"
    assert "Home Child" not in response.headers["Content-Disposition"]


@pytest.mark.parametrize("key, record_key, document_type, allowed", [
    ("administrator", "HOME", "birth_certificate", True), ("social_worker", "HOME", "birth_certificate", False),
    ("legal_officer", "HOME", "court_order", True), ("social_worker", "HOME", "medical_report", True),
    ("school_nurse", "SCHOOL", "medical_report", True), ("school_nurse", "SCHOOL", "birth_certificate", False),
    ("teacher", "SCHOOL", "medical_report", False), ("legal_officer", "HOME", "medical_report", False),
    ("administrator", "SCHOOL", "court_order", False),
])
def test_upload_permissions_follow_the_type_table(app, key, record_key, document_type, allowed):
    response = upload(app, sign_in(app, key), record_key, document_type)
    with app.app_context():
        assert (Document.query.count() == 1) is allowed
    if not allowed:
        assert response.status_code in (403, 404)


def test_home_manager_and_teacher_cannot_download(app):
    upload(app, sign_in(app, "legal_officer"))
    document = only_document(app)
    for key in ("home_manager", "teacher"):
        assert sign_in(app, key).get(f"/documents/{document.id}").status_code == 404


def test_blob_is_ciphertext_and_filename_is_encrypted(app):
    upload(app, sign_in(app, "legal_officer"))
    with app.app_context():
        blob = bytes(db.session.execute(text("SELECT ciphertext FROM document_blobs")).scalar())
        name = bytes(db.session.execute(text("SELECT original_filename FROM documents")).scalar())
    assert b"marker-d0c" not in blob and b"Home Child" not in name


def test_a_blob_moved_to_another_document_fails_cleanly(app):
    legal = sign_in(app, "legal_officer")
    upload(app, legal)
    upload(app, legal, name="second.pdf")
    with app.app_context():
        first, second = Document.query.order_by(Document.id).all()
        db.session.get(DocumentBlob, second.id).ciphertext = bytes(db.session.get(DocumentBlob, first.id).ciphertext)
        db.session.commit()
        second_id = second.id
    response = legal.get(f"/documents/{second_id}")
    assert response.status_code == 409 and b"marker-d0c" not in response.data
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="document_integrity_failed").count() == 1


@pytest.mark.parametrize("data, reason", [
    (b"MZ\x90\x00 fake executable", "type"),
    (b"%PDF-1.4 /JavaScript (app.alert(1))", "pdf_active_content"),
    (b"%PDF-1.4 /OpenAction << >>", "pdf_active_content"),
])
def test_dangerous_uploads_are_refused_and_audited(app, data, reason):
    upload(app, sign_in(app, "legal_officer"), data=data, name="innocent.pdf")
    with app.app_context():
        assert Document.query.count() == 0
        assert AuditLogEntry.query.filter_by(action="document_upload_refused").one().details.endswith(reason)


def test_images_are_reencoded_without_exif(app):
    upload(app, sign_in(app, "social_worker"), document_type="medical_report", data=png_with_exif(), name="scan.png")
    document = only_document(app)
    data = sign_in(app, "social_worker").get(f"/documents/{document.id}").data
    assert b"SecretCameraMaker" not in data
    with Image.open(io.BytesIO(data)) as image:
        assert image.size == (20, 20)


def test_oversized_images_are_refused(app, monkeypatch):
    monkeypatch.setattr(document_service, "MAX_IMAGE_SIDE", 10)
    upload(app, sign_in(app, "social_worker"), document_type="medical_report", data=png_with_exif(), name="big.png")
    with app.app_context():
        assert Document.query.count() == 0


def test_pixel_limit_is_set_explicitly():
    assert document_service.MAX_IMAGE_PIXELS == 25_000_000


def test_files_over_ten_megabytes_are_refused(app):
    upload(app, sign_in(app, "legal_officer"), data=b"%PDF-1.4" + b"0" * (10 * 1024 * 1024))
    with app.app_context():
        assert Document.query.count() == 0


def test_every_download_is_audited(app):
    upload(app, sign_in(app, "legal_officer"))
    document = only_document(app)
    worker = sign_in(app, "social_worker")
    worker.get(f"/documents/{document.id}")
    worker.get(f"/documents/{document.id}")
    with app.app_context():
        assert AuditLogEntry.query.filter_by(action="document_downloaded").count() == 2
        details = " ".join(r.details or "" for r in AuditLogEntry.query.all())
    assert "Home Child" not in details and "Order for" not in details


def test_deletion_needs_an_admin_code_bound_to_the_document(app, otp_codes):
    upload(app, sign_in(app, "legal_officer"))
    document = only_document(app)
    admin = sign_in(app, "administrator")
    admin.post(f"/documents/{document.id}/delete")
    admin.post(f"/documents/{document.id}/delete/confirm", data={"otp_code": "000000" if otp_codes[-1] != "000000" else "111111"})
    assert only_document(app).is_deleted is False
    admin.post(f"/documents/{document.id}/delete/confirm", data={"otp_code": otp_codes[-1]})
    assert only_document(app).is_deleted is True
    assert sign_in(app, "social_worker").get(f"/documents/{document.id}").status_code == 404
    with app.app_context():
        assert DocumentBlob.query.count() == 1  # soft delete: the encrypted file is kept


def test_non_admins_cannot_delete(app, otp_codes):
    upload(app, sign_in(app, "legal_officer"))
    document = only_document(app)
    assert sign_in(app, "legal_officer").post(f"/documents/{document.id}/delete").status_code == 403
    assert otp_codes == []


def test_blob_and_document_grants_are_registered():
    from app.db_roles import APPEND_ONLY_TABLES, COLUMN_UPDATE_TABLES

    assert "document_blobs" in APPEND_ONLY_TABLES
    assert COLUMN_UPDATE_TABLES["documents"] == ("is_deleted", "deleted_at")


@pytest.mark.parametrize("fmt, content_type, expected", [("PNG", "image/png", ["PNG"]), ("JPEG", "image/jpeg", ["JPEG"])])
def test_pillow_only_uses_the_detected_decoder(monkeypatch, fmt, content_type, expected):
    seen = []
    real_open = Image.open

    def spy(fp, mode="r", formats=None):
        seen.append(formats)
        return real_open(fp, mode, formats=formats)

    monkeypatch.setattr(Image, "open", spy)
    out = io.BytesIO()
    Image.new("RGB", (5, 5), "green").save(out, format=fmt)
    document_service.reencode_image(out.getvalue(), content_type)
    assert seen == [expected]


def test_mismatched_content_is_refused_by_the_restricted_decoder():
    out = io.BytesIO()
    Image.new("RGB", (5, 5), "green").save(out, format="PNG")
    with pytest.raises(document_service.DocumentError):
        document_service.reencode_image(out.getvalue(), "image/jpeg")  # PNG bytes, JPEG decoder only
