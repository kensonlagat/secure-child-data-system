"""CLI bootstrap and diagnostics commands."""

import os
import secrets
import subprocess
from datetime import datetime

import click
import re

from flask import current_app
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import db
from app.models.anomaly_alert import AnomalyAlert
from app.models.audit_log import AuditLogEntry
from app.models.school_class import SchoolClass, split_class_label
from app.models.user import Role, User
from app.services.anomaly_scoring import score_recent_entries
from app.services.anomaly_training import train_models_for_all_roles
from app.services.audit_service import log_action
from app.services.key_derivation import derive_subkey
from app.services.enrolment_service import assign_teacher
from app.services.synthetic_audit_data import generate_synthetic_history
from app.services.sms_service import SmsDeliveryError, send_sms

ROLE_SEED_DATA = (
    ("administrator", "both"),
    ("teacher", "school"),
    ("school_nurse", "school"),
    ("social_worker", "childrens_home"),
    ("legal_officer", "childrens_home"),
    ("parent_guardian", "school"),
    ("principal", "school"),
    ("home_manager", "childrens_home"),
)
SYNTHETIC_USER_CLASSES = ("Grade 4A", "Grade 5B", "Grade 6A", "Grade 7C", "Grade 8B")
CREDENTIALS_FILE_NAME = "TESTING_CREDENTIALS.md"  # local and git-ignored, never tracked
E164_PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")


def _create_synthetic_user(role: Role, sequence_number: int, password: str) -> User:
    """Create one synthetic user record for the requested role."""
    user = User()
    user.role_id = role.id
    user.role = role
    user.phone_number = f"+254700{role.id:02d}{sequence_number:04d}"
    user.password_hash = generate_password_hash(password)
    user.is_active = True

    if role.name == "administrator":
        user.full_name = f"Admin Analyst {sequence_number:02d}"
        user.email = f"synthetic.admin.{sequence_number:02d}@example.com"
    elif role.name == "teacher":
        user.full_name = f"Teacher Demo {sequence_number:02d}"
        user.email = f"synthetic.teacher.{sequence_number:02d}@example.com"
    elif role.name == "legal_officer":
        user.full_name = f"Legal Officer Demo {sequence_number:02d}"
        user.email = f"synthetic.legal.{sequence_number:02d}@example.com"
    else:
        raise click.ClickException(f"Unsupported synthetic seed role: {role.name}")

    return user


@click.command("seed-roles")
def seed_roles_command():
    """Create baseline system roles if they do not already exist."""
    created_count = 0
    skipped_count = 0

    for role_name, institution_mode in ROLE_SEED_DATA:
        existing = Role.query.filter_by(name=role_name).first()
        if existing:
            skipped_count += 1
            click.echo(f"Skipped existing role: {role_name}")
            continue

        role = Role()
        role.name = role_name
        role.institution_mode = institution_mode
        db.session.add(role)
        created_count += 1
        click.echo(f"Created role: {role_name} ({institution_mode})")

    db.session.commit()
    click.echo(f"Role seeding complete. Created: {created_count}, Skipped: {skipped_count}")


@click.command("create-admin")
@click.option("--email", required=True, help="Administrator email address.")
@click.option(
    "--password",
    required=False,
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Administrator password.",
)
@click.option("--full-name", "full_name", required=True, help="Administrator full name.")
@click.option("--phone", "phone_number", required=True, help="Administrator phone number.")
def create_admin_command(email: str, password: str, full_name: str, phone_number: str):
    """Create the first administrator account from a trusted local terminal."""
    admin_role = Role.query.filter_by(name="administrator").first()
    if admin_role is None:
        raise click.ClickException(
            "Administrator role not found. Run `flask seed-roles` first."
        )

    existing_user = User.query.filter(db.func.lower(User.email) == email.strip().lower()).first()
    if existing_user:
        raise click.ClickException(f"User with email '{email}' already exists.")

    user = User()
    user.email = email.strip()
    user.full_name = full_name.strip()
    user.phone_number = phone_number.strip()
    user.password_hash = generate_password_hash(password)
    user.role_id = admin_role.id

    db.session.add(user)
    db.session.commit()

    log_action(
        user_id=user.id,
        action="create_user",
        target_record_type="user",
        target_record_id=user.id,
        details="CLI bootstrap administrator account creation",
    )

    click.echo(f"Administrator account created with user_id={user.id} and email={user.email}")



@click.command("test-sms")
@click.option("--to", "phone_number", required=True, help="E.164 recipient phone number.")
def test_sms_command(phone_number: str):
    """Send a diagnostic SMS without exposing credentials or message contents."""
    if not E164_PHONE_PATTERN.fullmatch(phone_number):
        raise click.ClickException("Recipient must be a valid E.164 phone number.")

    username = os.environ.get("AFRICASTALKING_USERNAME")
    api_key = os.environ.get("AFRICASTALKING_API_KEY")
    click.echo(f"username set: {'yes' if username else 'no'}")
    click.echo(f"api key set: {'yes' if api_key else 'no'}")

    try:
        response = send_sms(phone_number, "Test message from the child data system.")
    except SmsDeliveryError as error:
        click.echo(f"send failed: SmsDeliveryError (status {error.status_code})")
        return
    except Exception as error:
        # Type only: exception text from the HTTP stack is not needed and may echo request details.
        click.echo(f"send failed: {type(error).__name__}")
        return

    recipients = response.get("SMSMessageData", {}).get("Recipients", [])
    for recipient in recipients:
        for field_name, field_value in recipient.items():
            click.echo(f"{field_name}: {field_value}")


@click.command("generate-synthetic-audit-data")
@click.option("--days", default=30, show_default=True, type=click.IntRange(min=1), help="Number of days of history to generate.")
def generate_synthetic_audit_data_command(days: int):
    """Generate clearly synthetic audit data for anomaly-detection training."""
    with db.session.begin():
        summary = generate_synthetic_history(db.session, days=days)

    click.echo(f"Generated synthetic audit data for {days} days.")
    for role_name, counts in summary.items():
        click.echo(f"{role_name}: normal={counts['normal']} anomalous={counts['anomalous']}")


@click.command("clear-synthetic-audit-data")
def clear_synthetic_audit_data_command():
    """Delete synthetic audit rows only.

    This is the one sanctioned exception to the audit log's append-only rule,
    and it is limited strictly to rows explicitly marked synthetic for testing
    and training data regeneration.
    """
    dialect = db.engine.dialect.name
    try:
        deleted_count = _purge_synthetic_rows(dialect)
        # Every purge leaves a real (non-synthetic) audit row with the count. log_action()
        # commits the deletion and this row together, so a purge can never go unrecorded:
        # if the audit insert fails, the deletion is rolled back with it.
        log_action(
            action="purge_synthetic_audit_data",
            attempted_identifier="cli:clear-synthetic-audit-data",
            target_record_type="audit_log",
            details=f"Purged {deleted_count} synthetic audit rows",
        )
    except Exception:
        db.session.rollback()
        raise
    click.echo(f"Deleted {deleted_count} synthetic audit rows.")


def _purge_synthetic_rows(dialect: str) -> int:
    """Delete synthetic audit rows without committing and return how many went."""
    if dialect == "postgresql":
        # The app's database role has no DELETE on the audit log (#72). This SECURITY
        # DEFINER function is the restricted path: it can only delete is_synthetic rows.
        return db.session.execute(text("SELECT purge_synthetic_audit_entries()")).scalar()
    if dialect == "sqlite":
        return _delete_synthetic_rows_directly()
    raise click.ClickException(f"Unsupported database for synthetic purge: {dialect}")


def _delete_synthetic_rows_directly() -> int:
    """Delete synthetic audit rows without committing. SQLite has no roles or
    functions, so this path is for tests only."""
    synthetic_entry_ids = [
        entry_id
        for (entry_id,) in db.session.query(AuditLogEntry.id)
        .filter(AuditLogEntry.is_synthetic.is_(True))
        .all()
    ]
    if synthetic_entry_ids:
        db.session.query(AnomalyAlert).filter(
            AnomalyAlert.audit_log_entry_id.in_(synthetic_entry_ids)
        ).delete(synchronize_session=False)

    deleted_count = (
        db.session.query(AuditLogEntry)
        .filter(AuditLogEntry.is_synthetic.is_(True))
        .delete(synchronize_session=False)
    )
    return deleted_count


@click.command("seed-synthetic-users")
@click.option(
    "--per-role",
    default=3,
    show_default=True,
    type=click.IntRange(min=1),
    help="Number of additional synthetic users to create per supported role.",
)
def seed_synthetic_users_command(per_role: int):
    """Create additional synthetic users for anomaly-training demos.

    Each run gets one random password, written only to the local git-ignored credentials
    file and never printed. The command refuses to run unless git confirms that file is
    ignored, so a password can never land in a tracked file.
    """
    credentials_path = _credentials_file_path()
    if not _is_git_ignored(credentials_path):
        raise click.ClickException(
            f"{CREDENTIALS_FILE_NAME} is not git-ignored (or git is unavailable), so no password "
            "can be written safely. No accounts were created."
        )

    supported_roles = ("administrator", "teacher", "legal_officer")
    password = secrets.token_urlsafe(18)
    created = []

    for role_name in supported_roles:
        role = Role.query.filter_by(name=role_name).first()
        if role is None:
            raise click.ClickException(f"Role '{role_name}' not found. Run `flask seed-roles` first.")

        existing_count = User.query.filter_by(role_id=role.id).count()
        for offset in range(1, per_role + 1):
            sequence_number = existing_count + offset
            user = _create_synthetic_user(role, sequence_number, password)
            db.session.add(user)
            db.session.flush()
            created.append(user.email)
            if role_name == "teacher":
                # Teachers get a class through the class link (#48), not free text.
                label = SYNTHETIC_USER_CLASSES[(sequence_number - 1) % len(SYNTHETIC_USER_CLASSES)]
                assign_teacher(None, _synthetic_class(label), user, audit=False)
            click.echo(f"Created {role_name} user_id={user.id} email={user.email}")

    # log_action() commits the accounts together with this row.
    log_action(
        action="seed_synthetic_users",
        attempted_identifier="cli:seed-synthetic-users",
        target_record_type="user",
        details=f"Created {len(created)} synthetic accounts",
    )

    # Written after the commit: if this fails, the new accounts have a password nobody knows
    # (fail closed) rather than a known password with no accounts behind it.
    try:
        _append_credentials(credentials_path, created, password)
    except OSError as error:
        raise click.ClickException(
            f"Accounts were created, but writing {CREDENTIALS_FILE_NAME} failed "
            f"({type(error).__name__}). Their password is unknown; rerun to create usable accounts."
        )
    click.echo(f"Password for these accounts written to {CREDENTIALS_FILE_NAME} (git-ignored, not shown).")


def _credentials_file_path() -> str:
    return os.path.join(os.path.dirname(current_app.root_path), CREDENTIALS_FILE_NAME)


def _is_git_ignored(path: str) -> bool:
    """True only when git confirms the path is ignored. Any doubt means False."""
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", path],
            cwd=os.path.dirname(path), capture_output=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _append_credentials(path: str, emails, password: str) -> None:
    lines = [f"\nSynthetic accounts seeded {datetime.now():%Y-%m-%d %H:%M} (seed-synthetic-users):"]
    lines += [f"- `{email}` / `{password}`" for email in emails]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _synthetic_class(label):
    """The active class for this label in the current academic year, created if missing."""
    name, stream = split_class_label(label)
    year = datetime.now().year
    school_class = SchoolClass.query.filter_by(name=name, stream=stream, academic_year=year).first()
    if school_class is None:
        school_class = SchoolClass(name=name, stream=stream, academic_year=year, is_active=True)
        db.session.add(school_class)
        db.session.flush()
    return school_class


@click.command("train-anomaly-models")
def train_anomaly_models_command():
    """Train role-specific Isolation Forest models from audit history."""
    summary = train_models_for_all_roles(db.session)

    for role_name, result in summary.items():
        click.echo(
            f"{role_name}: trained={result['trained']} "
            f"training_rows={result['training_rows']} "
            f"reason_skipped={result['reason_skipped']}"
        )


@click.command("score-anomalies")
@click.option(
    "--since-hours",
    default=24,
    show_default=True,
    type=click.IntRange(min=1),
    help="Score audit entries from the last N hours.",
)
def score_anomalies_command(since_hours: int):
    """Score recent audit entries and persist any new anomaly alerts."""
    alerts = score_recent_entries(db.session, since_hours=since_hours)
    if alerts:
        db.session.add_all(alerts)
    db.session.commit()

    per_role_counts = {}
    for alert in alerts:
        per_role_counts[alert.role_name] = per_role_counts.get(alert.role_name, 0) + 1

    click.echo(f"Created {len(alerts)} new anomaly alerts.")
    for role_name in sorted(per_role_counts):
        click.echo(f"{role_name}: {per_role_counts[role_name]}")


def _libpq_dsn(url):
    """Turn a SQLAlchemy URL into a libpq connection string (drop the +driver suffix)."""
    return url.replace("postgresql+psycopg2://", "postgresql://", 1)


@click.command("setup-db-roles")
@click.option("--owner-role", default="cds_owner", show_default=True, help="Role that owns the schema and runs migrations.")
@click.option("--app-role", default="cds_app", show_default=True, help="Low-privilege role the web app connects as.")
def setup_db_roles_command(owner_role, app_role):
    """Create or update the owner and app database roles and apply least-privilege grants.

    Run as a PostgreSQL superuser. The connection comes from DB_SETUP_URL, or DATABASE_URL
    if that is unset. Passwords come from CDS_OWNER_PASSWORD and CDS_APP_PASSWORD, or a
    hidden prompt (leave it empty to keep an existing role's password). Nothing secret is
    printed or written to a file.
    """
    from flask import current_app

    from app.db_roles import setup_roles

    dsn = _libpq_dsn(os.environ.get("DB_SETUP_URL") or current_app.config["SQLALCHEMY_DATABASE_URI"])

    def password_for(variable, role):
        value = os.environ.get(variable)
        if value is None:
            value = click.prompt(
                f"Password for {role} (empty keeps the current one)",
                hide_input=True, default="", show_default=False,
            )
        return value or None

    try:
        steps = setup_roles(
            dsn,
            owner_role,
            app_role,
            owner_password=password_for("CDS_OWNER_PASSWORD", owner_role),
            app_password=password_for("CDS_APP_PASSWORD", app_role),
            rls_key=derive_subkey("rls-context"),  # #19: stored owner-only, never printed
        )
    except (ValueError, PermissionError) as error:
        raise click.ClickException(str(error)) from None
    for step in steps:
        click.echo(step)


@click.command("check-db-privileges")
def check_db_privileges_command():
    """Prove that DATABASE_URL's role cannot change or delete audit rows (#72)."""
    from flask import current_app

    from app.db_roles import check_privileges

    from app.rls import context_values

    ok, lines = check_privileges(_libpq_dsn(current_app.config["SQLALCHEMY_DATABASE_URI"]),
                                 signed_context=context_values("", "system", ""))
    for line in lines:
        click.echo(line)
    if not ok:
        raise click.ClickException("Database privileges are not least-privilege.")


@click.command("create-backup-key")
@click.option("--path", "key_path", required=True, help="Where to write the key. Must be outside the project folder.")
def create_backup_key_command(key_path):
    """Write a new random backup key to a file (#69). The key is never printed."""
    from app.services.backup_service import BackupError, create_key_file
    try:
        create_key_file(key_path)
    except BackupError as error:
        if error.diagnostic:
            click.echo(f"Tool output (console only): {error.diagnostic}", err=True)
        raise click.ClickException(str(error)) from None
    click.echo("Backup key written. Set BACKUP_KEY_FILE to its path in .env and keep a copy somewhere safe:")
    click.echo("without it, the backups can't be restored.")


@click.command("backup-db")
@click.option("--no-prune", is_flag=True, help="Skip the retention clean-up after the backup.")
def backup_db_command(no_prune):
    """Dump the database as the owner role, encrypt it and apply the retention policy (#69)."""
    from app.services.backup_service import BackupError, create_backup, prune
    try:
        target = create_backup()
        click.echo(f"Encrypted backup written: {target.name} ({target.stat().st_size} bytes)")
        if not no_prune:
            deleted = prune()
            click.echo(f"Retention: {len(deleted)} old backup(s) deleted.")
    except BackupError as error:
        if error.diagnostic:
            click.echo(f"Tool output (console only): {error.diagnostic}", err=True)
        raise click.ClickException(str(error)) from None


@click.command("restore-test")
@click.option("--file", "backup_file", required=True, type=click.Path(exists=True, dir_okay=False),
              help="An encrypted backup made by backup-db.")
def restore_test_command(backup_file):
    """Restore a backup into a scratch database, compare row counts, then drop it (#69).

    Needs DB_SETUP_URL (a role that can create databases) set in the shell, as setup-db-roles does.
    """
    from app.services.backup_service import BackupError, restore_test
    try:
        restored = restore_test(backup_file)
    except BackupError as error:
        if error.diagnostic:
            click.echo(f"Tool output (console only): {error.diagnostic}", err=True)
        raise click.ClickException(str(error)) from None
    click.echo(f"Restore test passed: {len(restored)} tables, {sum(restored.values())} rows.")


@click.command("decrypt-backup")
@click.option("--file", "backup_file", required=True, type=click.Path(exists=True, dir_okay=False),
              help="An encrypted backup made by backup-db.")
def decrypt_backup_command(backup_file):
    """Write a backup's decrypted dump to standard output, for piping into pg_restore (#69).

    It never writes a file itself and refuses a terminal. An operator who holds the key could still
    redirect the output into a file, so the plaintext's safety depends on how it is piped.
    """
    import sys

    from app.services.backup_service import BackupError, decrypt_for_restore
    if sys.stdout.isatty():
        raise click.ClickException("Pipe the output into pg_restore; it is never written to a terminal or file.")
    try:
        dump = decrypt_for_restore(backup_file)
    except BackupError as error:
        raise click.ClickException(str(error)) from None
    sys.stdout.buffer.write(dump)
    sys.stdout.buffer.flush()


def _as_system(callback):
    """Run a CLI command inside the signed `system` row-level security context (#19, D19.3).
    This is the only way to get that context: web requests never pass through here."""
    import functools

    from app.rls import system_context

    if getattr(callback, "_runs_as_system", False):
        return callback  # create_app runs many times (tests); wrap once

    @functools.wraps(callback)
    def wrapped(*args, **kwargs):
        from flask import has_app_context

        if not has_app_context():
            return callback(*args, **kwargs)  # no app, so no database: nothing to scope
        with system_context():
            return callback(*args, **kwargs)

    wrapped._runs_as_system = True
    return wrapped


def register_cli_commands(app):
    """Attach project bootstrap CLI commands to the Flask app instance."""
    seed_roles_command.callback = _as_system(seed_roles_command.callback)
    app.cli.add_command(seed_roles_command)
    create_admin_command.callback = _as_system(create_admin_command.callback)
    app.cli.add_command(create_admin_command)
    setup_db_roles_command.callback = _as_system(setup_db_roles_command.callback)
    app.cli.add_command(setup_db_roles_command)
    check_db_privileges_command.callback = _as_system(check_db_privileges_command.callback)
    app.cli.add_command(check_db_privileges_command)
    test_sms_command.callback = _as_system(test_sms_command.callback)
    app.cli.add_command(test_sms_command)
    seed_synthetic_users_command.callback = _as_system(seed_synthetic_users_command.callback)
    app.cli.add_command(seed_synthetic_users_command)
    generate_synthetic_audit_data_command.callback = _as_system(generate_synthetic_audit_data_command.callback)
    app.cli.add_command(generate_synthetic_audit_data_command)
    clear_synthetic_audit_data_command.callback = _as_system(clear_synthetic_audit_data_command.callback)
    app.cli.add_command(clear_synthetic_audit_data_command)
    train_anomaly_models_command.callback = _as_system(train_anomaly_models_command.callback)
    app.cli.add_command(train_anomaly_models_command)
    score_anomalies_command.callback = _as_system(score_anomalies_command.callback)
    app.cli.add_command(score_anomalies_command)
    create_backup_key_command.callback = _as_system(create_backup_key_command.callback)
    app.cli.add_command(create_backup_key_command)
    backup_db_command.callback = _as_system(backup_db_command.callback)
    app.cli.add_command(backup_db_command)
    restore_test_command.callback = _as_system(restore_test_command.callback)
    app.cli.add_command(restore_test_command)
    decrypt_backup_command.callback = _as_system(decrypt_backup_command.callback)
    app.cli.add_command(decrypt_backup_command)
