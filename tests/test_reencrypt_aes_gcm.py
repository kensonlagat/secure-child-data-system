"""AES-GCM for the sensitive child record columns (#88): random nonces, tamper handling
without a 500, and the re-encryption migration."""

import importlib.util
import warnings
from datetime import date
from pathlib import Path

import pytest
import sqlalchemy as sa
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.encryption import UNREADABLE
from app.models.user import Role, User

PASSWORD = "Password#2026"
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "f5b2d8e1a7c3_reencrypt_child_records_aes_gcm.py"


@pytest.fixture()
def key(monkeypatch):
    value = Fernet.generate_key().decode()
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", value)
    return value


@pytest.fixture()
def app(key):
    application = create_app("testing")
    application.config["FIELD_ENCRYPTION_KEY"] = key
    with application.app_context():
        db.create_all()
        role = Role(name="administrator", institution_mode="both")
        db.session.add(role)
        db.session.flush()
        db.session.add(User(email="admin@example.com", full_name="Admin", phone_number="+254700000001",
                            password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True))
        first = ChildRecord(full_name="Same Name", date_of_birth=date(2014, 1, 1), institution_mode="school",
                            guardian_contact="+254711111111", medical_notes="Peanut allergy (marker-91c2)")
        second = ChildRecord(full_name="Same Name", date_of_birth=date(2014, 1, 1), institution_mode="school")
        db.session.add_all([first, second])
        db.session.commit()
        application.config.update(FIRST=first.id, SECOND=second.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def raw(app, record_id, column="full_name"):
    with app.app_context():
        return db.session.execute(text(f"SELECT {column} FROM child_records WHERE id = :id"), {"id": record_id}).scalar()


def tamper(app, record_id, column="medical_notes"):
    with app.app_context():
        stored = bytearray(raw(app, record_id, column))
        middle = len(stored) // 2  # a fully significant base64 character, never padding bits
        stored[middle] = ord("A") if stored[middle] != ord("A") else ord("B")  # still valid base64, wrong tag
        db.session.execute(text(f"UPDATE child_records SET {column} = :v WHERE id = :id"),
                           {"v": bytes(stored), "id": record_id})
        db.session.commit()


def sign_in(app):
    client = app.test_client()
    assert client.post("/login", data={"email": "admin@example.com", "password": PASSWORD,
                                       "portal": "school"}).status_code == 302
    return client


# --- New writes use AES-GCM -----------------------------------------------------------


def test_equal_names_are_stored_as_different_ciphertexts(app):
    assert raw(app, app.config["FIRST"]) != raw(app, app.config["SECOND"])


def test_values_still_read_back(app):
    with app.app_context():
        record = db.session.get(ChildRecord, app.config["FIRST"])
        assert (record.full_name, record.guardian_contact) == ("Same Name", "+254711111111")


# --- Tampered values never become a 500 ----------------------------------------------


def test_tampered_value_reads_as_unreadable_without_a_500(app):
    tamper(app, app.config["FIRST"])
    client = sign_in(app)

    html = client.get("/school/records", headers={"Accept": "text/html"})
    rows = client.get("/school/records", headers={"Accept": "application/json"})

    assert html.status_code == 200 and rows.status_code == 200
    notes = {row["id"]: row["medical_notes"] for row in rows.get_json()}
    assert notes[app.config["FIRST"]] == UNREADABLE
    assert "marker-91c2" not in html.get_data(as_text=True)


def test_tampered_value_is_audited_once_per_request_without_the_value(app):
    tamper(app, app.config["FIRST"])
    tamper(app, app.config["FIRST"], "guardian_contact")
    sign_in(app).get("/school/records", headers={"Accept": "application/json"})

    with app.app_context():
        rows = AuditLogEntry.query.filter_by(action="encrypted_value_unreadable").all()
    assert len(rows) == 1
    assert rows[0].details.startswith("2 encrypted value(s) failed")
    assert "+2547" not in rows[0].details


def test_the_unreadable_marker_can_never_be_saved(app):
    tamper(app, app.config["FIRST"])
    response = sign_in(app).patch(f"/school/records/{app.config['FIRST']}", json={"medical_notes": UNREADABLE})

    assert response.status_code == 400
    with app.app_context():
        # Re-assigning the marker to the tampered field is not a change, so nothing is written.
        # Assigning it anywhere else is refused by the column type itself.
        record = db.session.get(ChildRecord, app.config["SECOND"])
        record.medical_notes = UNREADABLE
        with pytest.raises(Exception, match="unreadable marker"):
            db.session.flush()
        db.session.rollback()


def test_other_fields_of_a_record_with_a_tampered_value_can_still_be_edited(app):
    tamper(app, app.config["FIRST"])
    response = sign_in(app).patch(f"/school/records/{app.config['FIRST']}", json={"guardian_contact": "+254722222222"})

    assert response.status_code == 200
    assert raw(app, app.config["FIRST"], "medical_notes") is not None  # tampered ciphertext kept as evidence


# --- The migration --------------------------------------------------------------------


def legacy_type(key):
    from sqlalchemy_utils import EncryptedType
    from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return EncryptedType(sa.String, key, AesEngine, "pkcs5")


def write_legacy(app, key, values):
    """Store values exactly as the old AesEngine columns did."""
    legacy = legacy_type(key)
    with app.app_context():
        dialect = db.engine.dialect
        ids = []
        for full_name, notes in values:
            record = ChildRecord(date_of_birth=date(2014, 1, 1), institution_mode="school", full_name="placeholder")
            db.session.add(record)
            db.session.flush()
            db.session.execute(text("UPDATE child_records SET full_name = :n, medical_notes = :m WHERE id = :id"), {
                "n": legacy.process_bind_param(full_name, dialect),
                "m": legacy.process_bind_param(notes, dialect) if notes is not None else None,
                "id": record.id,
            })
            ids.append(record.id)
        db.session.commit()
        return ids


def run_migration(app, direction="upgrade"):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    spec = importlib.util.spec_from_file_location("reencrypt_migration", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with app.app_context():
        db.session.remove()
        with db.engine.begin() as connection:
            module.op = Operations(MigrationContext.configure(connection))
            getattr(module, direction)()


def plaintexts(app, ids):
    with app.app_context():
        db.session.expire_all()
        return [(r.full_name, r.medical_notes) for r in ChildRecord.query.filter(ChildRecord.id.in_(ids)).order_by(ChildRecord.id)]


def test_migration_reencrypts_legacy_values_and_keeps_the_plaintext(app, key):
    ids = write_legacy(app, key, [("Twin Name", "note one"), ("Twin Name", None)])
    assert raw(app, ids[0]) == raw(app, ids[1])  # the old fixed-IV weakness

    run_migration(app)

    assert plaintexts(app, ids) == [("Twin Name", "note one"), ("Twin Name", None)]
    assert raw(app, ids[0]) != raw(app, ids[1])


def test_migration_rerun_changes_nothing(app, key):
    ids = write_legacy(app, key, [("Rerun", "x")])
    run_migration(app)
    before = raw(app, ids[0])

    run_migration(app)

    assert raw(app, ids[0]) == before


def test_downgrade_restores_the_legacy_format(app, key):
    ids = write_legacy(app, key, [("Back Again", "y")])
    run_migration(app)
    run_migration(app, "downgrade")

    legacy = legacy_type(key)
    with app.app_context():
        assert legacy.process_result_value(bytes(raw(app, ids[0])), db.engine.dialect) == "Back Again"


def test_migration_stops_and_changes_nothing_when_a_value_cannot_be_read(app, key):
    good, bad = write_legacy(app, key, [("Good", "fine"), ("Bad", "broken")])
    with app.app_context():
        db.session.execute(text("UPDATE child_records SET medical_notes = :v WHERE id = :id"),
                           {"v": b"not-a-ciphertext", "id": bad})
        db.session.commit()
    before = raw(app, good)

    with pytest.raises(RuntimeError, match="could not be read") as error:
        run_migration(app)

    assert raw(app, good) == before  # rolled back
    assert "broken" not in str(error.value) and "Good" not in str(error.value)
