"""Encrypted database backups, restore tests and retention (#69).

- pg_dump runs as the owner role from MIGRATION_DATABASE_URL. The password reaches libpq
  through a temporary PGPASSFILE that is deleted afterwards. It is never on a command line
  (where other local users could see it in the process list) and never printed.
- The dump is captured in memory and encrypted with AES-256-GCM before anything is written,
  so no plaintext dump ever touches the disk. The key is a separate 32-byte key read from
  BACKUP_KEY_FILE, which must be outside the project folder. It is not FIELD_ENCRYPTION_KEY
  or SECRET_KEY, so a copied .env alone does not open the backups.
- Just before pg_dump, the row count of every table is taken and stored as a small JSON
  manifest inside the encrypted file (length-prefixed, in front of the dump, covered by the
  same GCM tag). cds_app has no DELETE anywhere, so counts can only grow between the count
  and pg_dump's snapshot.
- A restore test decrypts in memory, pipes the dump into pg_restore for a fixed scratch
  database (never the live one), and requires every table to have at least its manifest
  count and no more than the live database has. Then it drops the scratch database.
- Retention keeps every backup from the last 7 days and the newest one from each of the 4
  weeks before that. Only files matching this module's own name pattern are ever deleted.
- Every backup, restore test, failure and deletion writes an audit row (no secrets, no data).
"""

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.audit_service import log_action

MAGIC = b"CDSBAK1\n"
NONCE_BYTES = 12
FILE_PATTERN = re.compile(r"^cds-(\d{8}-\d{6})\.dump\.enc$")
SCRATCH_DATABASE = "cds_restore_test"
KEEP_ALL_DAYS = 7
KEEP_WEEKLY_WEEKS = 4
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class BackupError(RuntimeError):
    """A safe message for the operator: names settings and steps, never secret values.

    `diagnostic` may hold the first line of a tool's stderr. It is printed to the console
    only, never written to the audit log."""

    def __init__(self, message, diagnostic=None):
        super().__init__(message)
        self.diagnostic = diagnostic


@dataclass(frozen=True)
class Connection:
    host: str
    port: int
    user: str
    password: str
    database: str


def parse_url(url, label):
    if not url:
        raise BackupError(f"{label} is not set.")
    parsed = urlparse(url.replace("postgresql+psycopg2://", "postgresql://", 1))
    if parsed.scheme != "postgresql" or not parsed.username or not parsed.path.strip("/"):
        raise BackupError(f"{label} is not a PostgreSQL URL with a user and database.")
    return Connection(host=parsed.hostname or "localhost", port=parsed.port or 5432,
                      user=unquote(parsed.username), password=unquote(parsed.password or ""),
                      database=parsed.path.strip("/"))


# --- Key ------------------------------------------------------------------------------------------


def _outside_project(path):
    resolved = Path(path).resolve()
    return PROJECT_ROOT != resolved and PROJECT_ROOT not in resolved.parents


def load_key(path):
    if not path:
        raise BackupError("BACKUP_KEY_FILE is not set. Create a key with `flask create-backup-key`.")
    if not _outside_project(path):
        raise BackupError("BACKUP_KEY_FILE must be outside the project folder.")
    try:
        key = base64.urlsafe_b64decode(Path(path).read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        raise BackupError("BACKUP_KEY_FILE could not be read as a backup key.") from None
    if len(key) != 32:
        raise BackupError("BACKUP_KEY_FILE does not hold a 32-byte key.")
    return key


def create_key_file(path):
    """Write a new random key. Refuses to overwrite or to write inside the project."""
    if not _outside_project(path):
        raise BackupError("The key file must be outside the project folder.")
    target = Path(path)
    if target.exists():
        raise BackupError("That key file already exists. It was not changed.")
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "x", encoding="ascii") as handle:
        handle.write(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def encrypt(key, data, filename):
    nonce = secrets.token_bytes(NONCE_BYTES)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC + filename.encode())


def pack(manifest, dump):
    """Manifest JSON (4-byte big-endian length first) followed by the dump. Encrypted as one."""
    encoded = json.dumps(manifest, sort_keys=True).encode()
    return len(encoded).to_bytes(4, "big") + encoded + dump


def unpack(plaintext):
    if len(plaintext) < 4:
        raise BackupError("The backup has no manifest.")
    length = int.from_bytes(plaintext[:4], "big")
    if length > len(plaintext) - 4:
        raise BackupError("The backup manifest is damaged.")
    try:
        manifest = json.loads(plaintext[4:4 + length])
        counts = manifest["row_counts"]
        if not isinstance(counts, dict) or not all(isinstance(v, int) and v >= 0 for v in counts.values()):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise BackupError("The backup manifest is damaged.") from None
    return manifest, plaintext[4 + length:]


def decrypt(key, blob, filename):
    from cryptography.exceptions import InvalidTag
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_BYTES + 16:
        raise BackupError("This is not a backup file made by this system.")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_BYTES]
    try:
        return AESGCM(key).decrypt(nonce, blob[len(MAGIC) + NONCE_BYTES:], MAGIC + filename.encode())
    except InvalidTag:
        raise BackupError("The backup failed its integrity check (wrong key, renamed or altered file).") from None


# --- Running the PostgreSQL tools -------------------------------------------------------------------


def _pgpass_escape(value):
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _tool(name):
    bin_dir = os.environ.get("PG_BIN_DIR")
    found = str(Path(bin_dir) / name) if bin_dir else shutil.which(name)
    if not found:
        raise BackupError(f"{name} was not found. Put PostgreSQL's bin folder on PATH or set PG_BIN_DIR.")
    return found


def run_pg(conn, tool, args, stdin=None):
    """Run a PostgreSQL client tool for conn. The password goes only into a temporary
    PGPASSFILE; the command line carries host, port, user and database, never a secret."""
    workdir = tempfile.mkdtemp(prefix="cds-pg-")
    pgpass = os.path.join(workdir, "pgpass.conf")
    try:
        with open(pgpass, "w", encoding="utf-8") as handle:
            handle.write(":".join([_pgpass_escape(conn.host), str(conn.port), "*",
                                   _pgpass_escape(conn.user), _pgpass_escape(conn.password)]) + "\n")
        try:
            os.chmod(pgpass, 0o600)
        except OSError:
            pass
        env = {key: value for key, value in os.environ.items() if key not in ("PGPASSWORD", "PGPASSFILE")}
        env["PGPASSFILE"] = pgpass
        command = [_tool(tool), "-h", conn.host, "-p", str(conn.port), "-U", conn.user, "--no-password", *args]
        result = subprocess.run(command, input=stdin, capture_output=True, env=env, check=False)
        if result.returncode != 0:
            # The first stderr line goes to the console only, for diagnosis; the audit row
            # gets the exit code. The password is never on the command line, so stderr can't echo it.
            first_line = (result.stderr or b"").decode("utf-8", "replace").strip().splitlines()[:1]
            raise BackupError(f"{tool} failed with exit code {result.returncode}.",
                              diagnostic=first_line[0][:300] if first_line else None)
        return result.stdout
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _audit(action, details):
    log_action(attempted_identifier="cli:backup", action=action,
               target_record_type="database_backup", details=details)


# --- Backup, restore test, retention --------------------------------------------------------------


def backup_dir():
    path = os.environ.get("BACKUP_DIR")
    if not path:
        raise BackupError("BACKUP_DIR is not set.")
    if not _outside_project(path):
        raise BackupError("BACKUP_DIR must be outside the project folder.")
    Path(path).mkdir(parents=True, exist_ok=True)
    return Path(path)


def create_backup(now=None, row_counts=None):
    """Count rows, dump as the owner, encrypt both in memory, write the file. Returns its path."""
    row_counts = row_counts or _row_counts
    now = now or datetime.now()
    try:
        key = load_key(os.environ.get("BACKUP_KEY_FILE"))
        owner = parse_url(os.environ.get("MIGRATION_DATABASE_URL"), "MIGRATION_DATABASE_URL")
        directory = backup_dir()
        filename = f"cds-{now:%Y%m%d-%H%M%S}.dump.enc"
        counts = row_counts(owner)
        dump = run_pg(owner, "pg_dump", ["-Fc", "-d", owner.database])
        if not dump:
            raise BackupError("pg_dump produced no output.")
        manifest = {"version": 1, "created": now.isoformat(timespec="seconds"), "row_counts": counts}
        target = directory / filename
        with open(target, "xb") as handle:
            handle.write(encrypt(key, pack(manifest, dump), filename))
    except BackupError as error:
        _audit("backup_failed", f"Backup failed: {error}")
        raise
    _audit("backup_created", f"Encrypted backup {filename} written ({target.stat().st_size} bytes, "
                             f"{len(counts)} tables, {sum(counts.values())} rows counted)")
    return target


def _row_counts(conn):
    import psycopg2
    with psycopg2.connect(host=conn.host, port=conn.port, user=conn.user, password=conn.password,
                          dbname=conn.database) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
        tables = [row[0] for row in cursor.fetchall()]
        counts = {}
        for table in tables:
            cursor.execute(f'SELECT count(*) FROM public."{table}"')  # names come from pg_tables
            counts[table] = cursor.fetchone()[0]
    connection.close()
    return counts


def restore_test(path, row_counts=_row_counts):
    """Restore a backup into the scratch database and compare it with the live one."""
    path = Path(path)
    try:
        if not FILE_PATTERN.match(path.name):
            raise BackupError("That file name is not a backup made by this system.")
        key = load_key(os.environ.get("BACKUP_KEY_FILE"))
        owner = parse_url(os.environ.get("MIGRATION_DATABASE_URL"), "MIGRATION_DATABASE_URL")
        admin = parse_url(os.environ.get("DB_SETUP_URL"), "DB_SETUP_URL")
        if SCRATCH_DATABASE in (owner.database, admin.database):
            raise BackupError("The scratch database name matches a live database. Nothing was restored.")
        manifest, dump = unpack(decrypt(key, path.read_bytes(), path.name))
        expected = manifest["row_counts"]
        maintenance = Connection(admin.host, admin.port, admin.user, admin.password, admin.database)
        run_pg(maintenance, "dropdb", ["--if-exists", SCRATCH_DATABASE])
        run_pg(maintenance, "createdb", [SCRATCH_DATABASE])
        try:
            run_pg(maintenance, "pg_restore", ["--exit-on-error", "-d", SCRATCH_DATABASE], stdin=dump)
            live = row_counts(owner)
            restored = row_counts(Connection(admin.host, admin.port, admin.user, admin.password, SCRATCH_DATABASE))
        finally:
            run_pg(maintenance, "dropdb", ["--if-exists", SCRATCH_DATABASE])
        # Every table counted at backup time must come back with at least that many rows (rows
        # are never deleted, so the dump can only hold more), and never more than live has now.
        missing = sorted(t for t in expected if t not in restored)
        short = sorted(t for t in expected if t in restored and restored[t] < expected[t])
        larger = sorted(t for t in restored if t in live and restored[t] > live[t])
        if missing or short or larger:
            raise BackupError(f"Restore check failed: {len(missing)} table(s) missing, {len(short)} with fewer "
                              f"rows than at backup time, {len(larger)} with more rows than the live database.")
    except BackupError as error:
        _audit("backup_restore_failed", f"Restore test of {path.name} failed: {error}")
        raise
    _audit("backup_restore_tested", f"Restore test of {path.name} passed: {len(restored)} tables, "
                                    f"{sum(restored.values())} rows")
    return restored


def decrypt_for_restore(path):
    """Return the decrypted dump of a backup, for piping into pg_restore. Audited."""
    path = Path(path)
    try:
        if not FILE_PATTERN.match(path.name):
            raise BackupError("That file name is not a backup made by this system.")
        key = load_key(os.environ.get("BACKUP_KEY_FILE"))
        _, dump = unpack(decrypt(key, path.read_bytes(), path.name))
    except BackupError as error:
        _audit("backup_decrypt_failed", f"Decrypting {path.name} failed: {error}")
        raise
    _audit("backup_decrypted", f"Backup {path.name} decrypted to a pipe for a restore")
    return dump


def select_for_deletion(names, now):
    """Return the backup names the retention policy no longer keeps."""
    dated = []
    for name in names:
        match = FILE_PATTERN.match(name)
        if match:
            dated.append((datetime.strptime(match.group(1), "%Y%m%d-%H%M%S"), name))
    keep = {name for stamp, name in dated if stamp >= now - timedelta(days=KEEP_ALL_DAYS)}
    newest_per_week = {}
    for stamp, name in sorted(dated):
        age = now - stamp
        if timedelta(days=KEEP_ALL_DAYS) < age <= timedelta(days=KEEP_ALL_DAYS + 7 * KEEP_WEEKLY_WEEKS):
            newest_per_week[stamp.isocalendar()[:2]] = name
    keep |= set(newest_per_week.values())
    return sorted(name for _, name in dated if name not in keep)


def prune(now=None):
    directory = backup_dir()
    doomed = select_for_deletion([p.name for p in directory.iterdir() if p.is_file()], now or datetime.now())
    for name in doomed:
        (directory / name).unlink()
        _audit("backup_deleted", f"Retention policy deleted backup {name}")
    return doomed
