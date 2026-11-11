"""CLI bootstrap commands for roles and first administrator account."""

import os

import click
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import db
from app.models.anomaly_alert import AnomalyAlert
from app.models.audit_log import AuditLogEntry
from app.models.user import Role, User
from app.services.anomaly_scoring import score_recent_entries
from app.services.anomaly_training import train_models_for_all_roles
from app.services.audit_service import log_action
from app.services.synthetic_audit_data import generate_synthetic_history

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


def _create_synthetic_user(role: Role, sequence_number: int) -> User:
    """Create one synthetic user record for the requested role."""
    user = User()
    user.role_id = role.id
    user.phone_number = f"+254700{role.id:02d}{sequence_number:04d}"
    user.password_hash = generate_password_hash("Synthetic#2026")
    user.is_active = True

    if role.name == "administrator":
        user.full_name = f"Admin Analyst {sequence_number:02d}"
        user.email = f"synthetic.admin.{sequence_number:02d}@example.com"
    elif role.name == "teacher":
        user.full_name = f"Teacher Demo {sequence_number:02d}"
        user.email = f"synthetic.teacher.{sequence_number:02d}@example.com"
        user.assigned_class = SYNTHETIC_USER_CLASSES[(sequence_number - 1) % len(SYNTHETIC_USER_CLASSES)]
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

    existing_user = User.query.filter_by(email=email).first()
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
    if dialect == "postgresql":
        # The app's database role has no DELETE on the audit log (#72). This SECURITY
        # DEFINER function is the restricted path: it can only delete is_synthetic rows.
        deleted_count = db.session.execute(
            text("SELECT purge_synthetic_audit_entries()")
        ).scalar()
        db.session.commit()
        click.echo(f"Deleted {deleted_count} synthetic audit rows.")
        return
    if dialect != "sqlite":
        raise click.ClickException(f"Unsupported database for synthetic purge: {dialect}")

    # SQLite (tests only): no roles or functions, so delete the synthetic rows directly.
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
    db.session.commit()
    click.echo(f"Deleted {deleted_count} synthetic audit rows.")


@click.command("seed-synthetic-users")
@click.option(
    "--per-role",
    default=3,
    show_default=True,
    type=click.IntRange(min=1),
    help="Number of additional synthetic users to create per supported role.",
)
def seed_synthetic_users_command(per_role: int):
    """Create additional synthetic users for anomaly-training demos."""
    supported_roles = ("administrator", "teacher", "legal_officer")

    for role_name in supported_roles:
        role = Role.query.filter_by(name=role_name).first()
        if role is None:
            raise click.ClickException(f"Role '{role_name}' not found. Run `flask seed-roles` first.")

        existing_count = User.query.filter_by(role_id=role.id).count()
        for offset in range(1, per_role + 1):
            sequence_number = existing_count + offset
            user = _create_synthetic_user(role, sequence_number)
            db.session.add(user)
            db.session.flush()
            click.echo(f"Created {role_name} user_id={user.id} email={user.email}")

    db.session.commit()


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

    ok, lines = check_privileges(_libpq_dsn(current_app.config["SQLALCHEMY_DATABASE_URI"]))
    for line in lines:
        click.echo(line)
    if not ok:
        raise click.ClickException("Database privileges are not least-privilege.")


def register_cli_commands(app):
    """Attach project bootstrap CLI commands to the Flask app instance."""
    app.cli.add_command(seed_roles_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(setup_db_roles_command)
    app.cli.add_command(check_db_privileges_command)
    app.cli.add_command(seed_synthetic_users_command)
    app.cli.add_command(generate_synthetic_audit_data_command)
    app.cli.add_command(clear_synthetic_audit_data_command)
    app.cli.add_command(train_anomaly_models_command)
    app.cli.add_command(score_anomalies_command)
