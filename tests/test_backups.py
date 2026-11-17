"""Encrypted backups, restore tests and retention (#69). PostgreSQL tools are mocked here; the
real dump and restore are exercised against the dev database by hand (see the PR)."""

import base64
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.services import backup_service as backups

OWNER_PASSWORD = "owner-pa:ss\\word-not-in-argv"
ADMIN_PASSWORD = "setup-secret-not-in-argv"
FAKE_DUMP = b"PGDMP fake custom-format dump with child data: Zawadi"
COUNTS = {"child_records": 3, "audit_log_entries": 9}


@pytest.fixture()
def app(monkeypatch, tmp_path):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    key_file = tmp_path / "keys" / "backup.key"
    backups.create_key_file(str(key_file))
    monkeypatch.setenv("BACKUP_KEY_FILE", str(key_file))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("MIGRATION_DATABASE_URL",
                       f"postgresql+psycopg2://cds_owner:{OWNER_PASSWORD.replace(':', '%3A').replace(chr(92), '%5C')}"
                       "@localhost:5432/child_data_system")
    monkeypatch.setenv("DB_SETUP_URL", f"postgresql://postgres:{ADMIN_PASSWORD}@localhost:5432/postgres")
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def tools(monkeypatch):
    """Record every PostgreSQL tool call: argv, env and the PGPASSFILE content at call time."""
    calls = []

    class Result:
        def __init__(self, stdout=b"", returncode=0):
            self.stdout, self.returncode, self.stderr = stdout, returncode, b""

    def fake_run(command, input=None, capture_output=True, env=None, check=False):
        pgpass = Path(env["PGPASSFILE"]).read_text(encoding="utf-8")
        calls.append({"argv": command, "env": env, "pgpass": pgpass, "stdin": input})
        return Result(FAKE_DUMP if os.path.basename(command[0]).startswith("pg_dump") else b"")

    monkeypatch.setattr(backups.subprocess, "run", fake_run)
    monkeypatch.setattr(backups, "_tool", lambda name: name)
    monkeypatch.setattr(backups, "_row_counts", lambda conn: dict(COUNTS))
    return calls


def audit(action):
    return AuditLogEntry.query.filter_by(action=action).all()


# --- Encryption -----------------------------------------------------------------------------------


def test_backup_is_encrypted_and_never_written_in_plaintext(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    blob = target.read_bytes()
    assert b"Zawadi" not in blob and b"PGDMP" not in blob
    manifest, dump = backups.unpack(backups.decrypt(backups.load_key(os.environ["BACKUP_KEY_FILE"]), blob,
                                                    target.name))
    assert dump == FAKE_DUMP
    assert manifest["row_counts"] == COUNTS
    assert [p.name for p in target.parent.iterdir()] == [target.name]


def test_wrong_key_renamed_or_altered_backups_fail_the_integrity_check(app, tools, tmp_path):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    key = backups.load_key(os.environ["BACKUP_KEY_FILE"])
    blob = target.read_bytes()
    with pytest.raises(backups.BackupError, match="integrity"):
        backups.decrypt(os.urandom(32), blob, target.name)
    with pytest.raises(backups.BackupError, match="integrity"):
        backups.decrypt(key, blob, "cds-20261117-090001.dump.enc")
    altered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(backups.BackupError, match="integrity"):
        backups.decrypt(key, altered, target.name)
    with pytest.raises(backups.BackupError, match="not a backup"):
        backups.decrypt(key, b"PGDMP plain dump", target.name)


def test_key_must_exist_be_outside_the_project_and_be_32_bytes(app, tmp_path, monkeypatch):
    with pytest.raises(backups.BackupError, match="not set"):
        backups.load_key(None)
    inside = backups.PROJECT_ROOT / "instance" / "backup.key"
    with pytest.raises(backups.BackupError, match="outside the project"):
        backups.load_key(str(inside))
    with pytest.raises(backups.BackupError, match="outside the project"):
        backups.create_key_file(str(inside))
    short = tmp_path / "short.key"
    short.write_text(base64.urlsafe_b64encode(b"x" * 16).decode())
    with pytest.raises(backups.BackupError, match="32-byte"):
        backups.load_key(str(short))


def test_creating_a_key_never_overwrites_and_never_prints_it(app, tmp_path):
    path = tmp_path / "new.key"
    result = app.test_cli_runner().invoke(args=["create-backup-key", "--path", str(path)])
    assert result.exit_code == 0
    key_text = path.read_text()
    assert key_text not in result.output
    again = app.test_cli_runner().invoke(args=["create-backup-key", "--path", str(path)])
    assert again.exit_code != 0 and "already exists" in again.output
    assert path.read_text() == key_text


# --- Passwords never on the command line ----------------------------------------------------------


def test_pg_dump_runs_as_the_owner_with_the_password_only_in_a_temporary_pgpass_file(app, tools, monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "leaked-from-shell")
    backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    call = tools[0]
    argv = " ".join(call["argv"])
    assert call["argv"][0] == "pg_dump"
    assert "-U cds_owner" in argv and "--no-password" in argv
    assert OWNER_PASSWORD not in argv
    assert "PGPASSWORD" not in call["env"]
    assert call["pgpass"].strip().endswith("cds_owner:" + OWNER_PASSWORD.replace("\\", "\\\\").replace(":", "\\:"))
    assert not Path(call["env"]["PGPASSFILE"]).exists()  # deleted afterwards


def test_a_tool_failure_still_deletes_the_pgpass_file_and_is_audited(app, monkeypatch):
    seen = []

    class Failed:
        returncode, stdout, stderr = 1, b"", b"connection refused"

    def failing(command, input=None, capture_output=True, env=None, check=False):
        seen.append(env["PGPASSFILE"])
        return Failed()

    monkeypatch.setattr(backups.subprocess, "run", failing)
    monkeypatch.setattr(backups, "_tool", lambda name: name)
    monkeypatch.setattr(backups, "_row_counts", lambda conn: dict(COUNTS))
    with pytest.raises(backups.BackupError, match="exit code 1"):
        backups.create_backup()
    assert not Path(seen[0]).exists()
    rows = audit("backup_failed")
    assert len(rows) == 1 and OWNER_PASSWORD not in rows[0].details
    assert list(Path(os.environ["BACKUP_DIR"]).iterdir()) == []


def test_backup_and_cli_output_never_contain_secrets(app, tools):
    result = app.test_cli_runner().invoke(args=["backup-db"])
    assert result.exit_code == 0, result.output
    key_text = Path(os.environ["BACKUP_KEY_FILE"]).read_text()
    for secret in (OWNER_PASSWORD, ADMIN_PASSWORD, key_text):
        assert secret not in result.output
        for row in AuditLogEntry.query.all():
            assert secret not in (row.details or "")
    created = audit("backup_created")
    assert len(created) == 1 and created[0].attempted_identifier == "cli:backup"


def test_backup_dir_inside_the_project_is_refused(app, tools, monkeypatch):
    monkeypatch.setenv("BACKUP_DIR", str(backups.PROJECT_ROOT / "backups"))
    with pytest.raises(backups.BackupError, match="outside the project"):
        backups.create_backup()
    assert len(audit("backup_failed")) == 1


# --- Restore test ---------------------------------------------------------------------------------


def test_restore_test_uses_only_the_scratch_database_and_is_audited(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    seen = []

    def row_counts(conn):
        seen.append(conn.database)
        return {**COUNTS, "audit_log_entries": 10} if conn.database == "child_data_system" else dict(COUNTS)

    restored = backups.restore_test(target, row_counts=row_counts)
    assert restored["child_records"] == 3
    restore_calls = [c for c in tools if c["argv"][0] == "pg_restore"]
    assert len(restore_calls) == 1
    assert restore_calls[0]["argv"][-1] == backups.SCRATCH_DATABASE
    assert restore_calls[0]["stdin"] == FAKE_DUMP  # decrypted in memory, piped, never written
    assert [c["argv"][0] for c in tools[1:]] == ["dropdb", "createdb", "pg_restore", "dropdb"]
    for call in tools[1:]:
        assert ADMIN_PASSWORD not in " ".join(call["argv"])
        assert "child_data_system" not in call["argv"]
    assert seen == ["child_data_system", backups.SCRATCH_DATABASE]
    assert len(audit("backup_restore_tested")) == 1


def test_restore_test_fails_on_missing_tables_and_still_drops_the_scratch_database(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))

    def row_counts(conn):
        return dict(COUNTS) if conn.database == "child_data_system" else {"audit_log_entries": 9}

    with pytest.raises(backups.BackupError, match="1 table"):
        backups.restore_test(target, row_counts=row_counts)
    assert tools[-1]["argv"][0] == "dropdb"
    assert len(audit("backup_restore_failed")) == 1


def test_restore_test_refuses_when_the_scratch_name_is_a_live_database(app, tools, monkeypatch):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    monkeypatch.setenv("MIGRATION_DATABASE_URL",
                       f"postgresql://cds_owner:x@localhost:5432/{backups.SCRATCH_DATABASE}")
    before = len(tools)
    with pytest.raises(backups.BackupError, match="matches a live database"):
        backups.restore_test(target, row_counts=lambda conn: {})
    assert len(tools) == before


def test_restore_test_refuses_files_not_made_by_backup_db(app, tools, tmp_path):
    other = tmp_path / "dump.sql"
    other.write_bytes(b"x")
    with pytest.raises(backups.BackupError, match="not a backup"):
        backups.restore_test(other, row_counts=lambda conn: {})
    assert len(audit("backup_restore_failed")) == 1


# --- Retention ------------------------------------------------------------------------------------


def name(stamp):
    return f"cds-{stamp:%Y%m%d-%H%M%S}.dump.enc"


def test_retention_keeps_a_week_of_backups_then_one_per_week_for_four_weeks():
    now = datetime(2026, 11, 17, 12, 0, 0)
    daily = [now - timedelta(days=day, hours=1) for day in range(0, 60)]
    doomed = set(backups.select_for_deletion([name(s) for s in daily] + ["notes.txt"], now))
    kept = {name(s) for s in daily} - doomed
    assert all(name(s) in kept for s in daily if now - s <= timedelta(days=7))
    older_kept = [s for s in daily if name(s) in kept and now - s > timedelta(days=7)]
    assert 4 <= len(older_kept) <= 5  # one per ISO week across 28 days
    assert all(now - s <= timedelta(days=35) for s in older_kept)
    assert "notes.txt" not in doomed


def test_prune_deletes_only_its_own_files_and_audits_each_deletion(app, tools):
    directory = backups.backup_dir()
    now = datetime(2026, 11, 17, 12, 0, 0)
    old = directory / name(now - timedelta(days=90))
    recent = directory / name(now - timedelta(days=1))
    foreign = directory / "cds-keep-me.dump.enc"
    for path in (old, recent, foreign):
        path.write_bytes(b"x")
    assert backups.prune(now) == [old.name]
    assert not old.exists() and recent.exists() and foreign.exists()
    assert len(audit("backup_deleted")) == 1


# --- Manifest (batch 5 review) --------------------------------------------------------------------


def test_a_restore_with_tables_present_but_empty_fails(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))

    def row_counts(conn):
        return dict(COUNTS) if conn.database == "child_data_system" else {table: 0 for table in COUNTS}

    with pytest.raises(backups.BackupError, match="2 with fewer rows than at backup time"):
        backups.restore_test(target, row_counts=row_counts)
    assert tools[-1]["argv"][0] == "dropdb"
    assert len(audit("backup_restore_failed")) == 1


def test_a_restore_with_more_rows_than_live_fails(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))

    def row_counts(conn):
        return dict(COUNTS) if conn.database == "child_data_system" else {**COUNTS, "child_records": 4}

    with pytest.raises(backups.BackupError, match="1 with more rows than the live database"):
        backups.restore_test(target, row_counts=row_counts)


def test_a_tampered_manifest_fails_the_integrity_check(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    blob = bytearray(target.read_bytes())
    # The manifest is the first plaintext after the magic and nonce; flip a byte there.
    blob[len(backups.MAGIC) + backups.NONCE_BYTES + 6] ^= 0x01
    target.write_bytes(bytes(blob))
    with pytest.raises(backups.BackupError, match="integrity"):
        backups.restore_test(target, row_counts=lambda conn: dict(COUNTS))
    assert [c["argv"][0] for c in tools] == ["pg_dump"]  # nothing was restored


def test_a_damaged_manifest_inside_a_valid_file_is_refused(app, tools):
    key = backups.load_key(os.environ["BACKUP_KEY_FILE"])
    filename = "cds-20261117-090000.dump.enc"
    target = backups.backup_dir() / filename
    target.write_bytes(backups.encrypt(key, (999).to_bytes(4, "big") + b"{}" + FAKE_DUMP, filename))
    with pytest.raises(backups.BackupError, match="manifest is damaged"):
        backups.restore_test(target, row_counts=lambda conn: dict(COUNTS))


def test_tool_stderr_reaches_the_console_but_never_the_audit_log(app, monkeypatch):
    class Failed:
        returncode, stdout = 1, b""
        stderr = b"pg_dump: error: connection to server failed: role-detail-xyz\nsecond line"

    monkeypatch.setattr(backups.subprocess, "run", lambda *a, **k: Failed())
    monkeypatch.setattr(backups, "_tool", lambda name: name)
    monkeypatch.setattr(backups, "_row_counts", lambda conn: dict(COUNTS))
    result = app.test_cli_runner().invoke(args=["backup-db"])
    assert result.exit_code != 0
    assert "role-detail-xyz" in result.stderr and "second line" not in result.stderr
    for row in AuditLogEntry.query.all():
        assert "role-detail-xyz" not in (row.details or "")


def test_decrypt_for_restore_returns_the_dump_and_is_audited(app, tools):
    target = backups.create_backup(datetime(2026, 11, 17, 9, 0, 0))
    assert backups.decrypt_for_restore(target) == FAKE_DUMP
    assert len(audit("backup_decrypted")) == 1
    other = target.parent / "renamed.dump.enc"
    target.rename(other)
    with pytest.raises(backups.BackupError, match="not a backup"):
        backups.decrypt_for_restore(other)
    assert len(audit("backup_decrypt_failed")) == 1
