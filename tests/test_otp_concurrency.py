"""verify_otp locks the OTP row, so one code cannot be used twice concurrently.

The race only exists on a real database with concurrent transactions, so the end-to-end
test runs against PostgreSQL when TEST_POSTGRES_URL points at a disposable database
(it creates and drops its own tables). Without it, only the query check runs.
"""

import os
import threading
import time
from datetime import datetime, timedelta

import pytest
from sqlalchemy.dialects import postgresql
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models.otp_event import OTPEvent
from app.models.user import Role, User
from app.services.otp_service import _locked_otp_query, verify_otp


def test_verify_otp_reads_the_row_with_select_for_update():
    app = create_app("testing")
    with app.app_context():
        statement = _locked_otp_query(1).statement
        compiled = str(statement.compile(dialect=postgresql.dialect()))
        assert "FOR UPDATE" in compiled


POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")


@pytest.mark.skipif(not POSTGRES_URL, reason="needs TEST_POSTGRES_URL (a disposable PostgreSQL database)")
@pytest.mark.parametrize("submitted", ["correct", "wrong"])
def test_concurrent_verifications_of_one_code_cannot_both_succeed(monkeypatch, submitted):
    import psycopg2

    from app.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLALCHEMY_DATABASE_URI", POSTGRES_URL)
    # Never hang the suite: any lock wait longer than 20 s fails the test instead.
    monkeypatch.setattr(
        TestingConfig, "SQLALCHEMY_ENGINE_OPTIONS", {"connect_args": {"options": "-c lock_timeout=20000"}}, raising=False
    )
    app = create_app("testing")
    code = "123456"
    with app.app_context():
        db.drop_all()
        db.create_all()
        role = Role(name="administrator", institution_mode="both")
        db.session.add(role)
        db.session.flush()
        user = User(email="a@example.com", full_name="A", phone_number="+254700000001",
                    password_hash="x", role_id=role.id)
        db.session.add(user)
        db.session.flush()
        otp = OTPEvent(user_id=user.id, action_context="test", code_hash=generate_password_hash(code),
                       expires_at=datetime.utcnow() + timedelta(minutes=5))
        db.session.add(otp)
        db.session.commit()
        otp_id = otp.id

    # Hold the row lock from another connection, as an in-flight verification would.
    holder = psycopg2.connect(POSTGRES_URL.replace("postgresql+psycopg2://", "postgresql://", 1))
    holder_cursor = holder.cursor()
    holder_cursor.execute("SELECT id FROM otp_events WHERE id = %s FOR UPDATE", (otp_id,))

    results = []

    def verify():
        with app.app_context():
            event = db.session.get(OTPEvent, otp_id)
            results.append(verify_otp(event, code if submitted == "correct" else "000000"))

    threads = [threading.Thread(target=verify) for _ in range(2 if submitted == "correct" else 7)]
    for thread in threads:
        thread.start()
    time.sleep(1.0)  # every thread is now waiting on the row lock
    assert results == []  # nobody got past the lock while it was held
    holder.rollback()
    holder.close()
    for thread in threads:
        thread.join(timeout=30)

    with app.app_context():
        final = db.session.get(OTPEvent, otp_id)
        is_verified, attempt_count = final.is_verified, final.attempt_count
        db.session.commit()  # end this read's transaction, or drop_all would wait on it
        db.drop_all()

    if submitted == "correct":
        assert sorted(results) == [False, True]  # exactly one request wins
        assert is_verified is True
    else:
        assert results == [False] * 7
        assert attempt_count == 5  # 7 concurrent guesses, never past the limit
