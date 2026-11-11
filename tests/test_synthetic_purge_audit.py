"""Every synthetic purge leaves a real audit row with the deleted count (#72 review).

`flask clear-synthetic-audit-data` is the one sanctioned deletion from the audit log, so
the deletion itself must be recorded. The SQLite path runs everywhere. The PostgreSQL path
(the SECURITY DEFINER function) runs when TEST_POSTGRES_URL points at a disposable database.
"""

import importlib.util
import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app import create_app, db
from app.models.audit_log import AuditLogEntry

PURGE_ACTION = "purge_synthetic_audit_data"


def _add_rows(synthetic_flags):
    for synthetic in synthetic_flags:
        db.session.add(AuditLogEntry(action="login", attempted_identifier="x",
                                     is_synthetic=synthetic, timestamp=datetime.utcnow()))
    db.session.commit()


def _purge(app):
    with app.app_context():  # the real `flask` command pushes this itself
        return app.test_cli_runner().invoke(args=["clear-synthetic-audit-data"])


def _purge_rows():
    return AuditLogEntry.query.filter_by(action=PURGE_ACTION).all()


@pytest.fixture()
def sqlite_app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


def test_purge_writes_a_real_audit_row_with_the_count(sqlite_app):
    with sqlite_app.app_context():
        _add_rows([True, True, True, False])

    result = _purge(sqlite_app)

    assert result.exit_code == 0, result.output
    with sqlite_app.app_context():
        rows = _purge_rows()
        assert len(rows) == 1
        assert rows[0].is_synthetic is False
        assert rows[0].details == "Purged 3 synthetic audit rows"
        assert rows[0].attempted_identifier == "cli:clear-synthetic-audit-data"
        assert AuditLogEntry.query.filter_by(is_synthetic=True).count() == 0


def test_purge_with_nothing_to_delete_is_still_recorded(sqlite_app):
    result = _purge(sqlite_app)

    assert result.exit_code == 0, result.output
    with sqlite_app.app_context():
        assert [row.details for row in _purge_rows()] == ["Purged 0 synthetic audit rows"]


def test_purge_rows_survive_later_purges(sqlite_app):
    _purge(sqlite_app)
    with sqlite_app.app_context():
        _add_rows([True])
    _purge(sqlite_app)

    with sqlite_app.app_context():
        assert [row.details for row in _purge_rows()] == [
            "Purged 0 synthetic audit rows",
            "Purged 1 synthetic audit rows",
        ]


def test_failed_audit_write_rolls_the_deletion_back(sqlite_app, monkeypatch):
    with sqlite_app.app_context():
        _add_rows([True, True])

    def failing_log_action(**kwargs):
        raise RuntimeError("audit insert failed")

    monkeypatch.setattr("app.cli.log_action", failing_log_action)
    result = _purge(sqlite_app)

    assert result.exit_code != 0
    with sqlite_app.app_context():
        db.session.remove()
        assert AuditLogEntry.query.filter_by(is_synthetic=True).count() == 2
        assert _purge_rows() == []


POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "versions" / (
    "d7f1b3c5e9a2_add_purge_synthetic_audit_function.py"
)


def _install_purge_function(connection):
    """Run the real migration's upgrade() against this connection."""
    spec = importlib.util.spec_from_file_location("purge_migration", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.op = SimpleNamespace(get_bind=lambda: connection,
                                execute=lambda sql: connection.execute(text(sql)))
    module.upgrade()


@pytest.mark.skipif(not POSTGRES_URL, reason="needs TEST_POSTGRES_URL (a disposable PostgreSQL database)")
def test_postgres_purge_through_the_function_writes_a_real_audit_row(monkeypatch):
    from app.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLALCHEMY_DATABASE_URI", POSTGRES_URL)
    monkeypatch.setattr(
        TestingConfig, "SQLALCHEMY_ENGINE_OPTIONS", {"connect_args": {"options": "-c lock_timeout=20000"}}, raising=False
    )
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        with db.engine.begin() as connection:
            _install_purge_function(connection)
        _add_rows([True, True, False])

    try:
        result = _purge(app)

        assert result.exit_code == 0, result.output
        with app.app_context():
            rows = _purge_rows()
            assert len(rows) == 1
            assert rows[0].is_synthetic is False
            assert rows[0].details == "Purged 2 synthetic audit rows"
            assert AuditLogEntry.query.filter_by(is_synthetic=True).count() == 0
            assert AuditLogEntry.query.filter_by(action="login").count() == 1
    finally:
        with app.app_context():
            db.session.commit()
            db.session.execute(text("DROP FUNCTION IF EXISTS purge_synthetic_audit_entries()"))
            db.session.commit()
            db.drop_all()
