"""Sensitive columns are stored as ciphertext (hard rule 5)."""

from datetime import date

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text

from app import create_app, db
from app.config import BaseConfig
from app.models.child_record import ChildRecord

SENSITIVE = {
    "full_name": "Wanjiru Kamau Test",
    "guardian_contact": "+254798765432",
    "medical_notes": "Asthma; inhaler in bag (marker-7f3a)",
}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        record = ChildRecord(date_of_birth=date(2014, 1, 1), institution_mode="school", **SENSITIVE)
        db.session.add(record)
        db.session.commit()
        application.config["RECORD"] = record.id
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def raw_row(app):
    with app.app_context():
        return db.session.execute(
            text("SELECT full_name, guardian_contact, medical_notes FROM child_records WHERE id = :id"),
            {"id": app.config["RECORD"]},
        ).one()


@pytest.mark.parametrize("column", sorted(SENSITIVE))
def test_raw_column_holds_no_plaintext(app, column):
    stored = getattr(raw_row(app), column)
    stored_text = stored.decode("latin-1") if isinstance(stored, (bytes, bytearray)) else str(stored)

    assert stored is not None
    assert SENSITIVE[column] not in stored_text
    assert SENSITIVE[column].split()[0] not in stored_text


def test_orm_reads_the_plaintext_back(app):
    with app.app_context():
        record = db.session.get(ChildRecord, app.config["RECORD"])
        assert {column: getattr(record, column) for column in SENSITIVE} == SENSITIVE


def test_a_different_key_cannot_read_the_values(app, monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with app.app_context():
        db.session.expire_all()
        try:
            record = db.session.get(ChildRecord, app.config["RECORD"])
            values = {column: getattr(record, column) for column in SENSITIVE}
        except Exception:
            return  # refused outright: fine
        assert values != SENSITIVE
