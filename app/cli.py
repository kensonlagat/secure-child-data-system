"""CLI bootstrap commands for roles and first administrator account."""

import click
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


def register_cli_commands(app):
    """Attach project bootstrap CLI commands to the Flask app instance."""
    app.cli.add_command(seed_roles_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(seed_synthetic_users_command)
    app.cli.add_command(generate_synthetic_audit_data_command)
    app.cli.add_command(clear_synthetic_audit_data_command)
    app.cli.add_command(train_anomaly_models_command)
    app.cli.add_command(score_anomalies_command)
