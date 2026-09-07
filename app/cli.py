"""CLI bootstrap commands for roles and first administrator account."""

import click
from werkzeug.security import generate_password_hash

from app import db
from app.models.user import Role, User
from app.services.audit_service import log_action

ROLE_SEED_DATA = (
    ("administrator", "both"),
    ("teacher", "school"),
    ("school_nurse", "school"),
    ("social_worker", "childrens_home"),
    ("legal_officer", "childrens_home"),
    ("parent_guardian", "school"),
)


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


def register_cli_commands(app):
    """Attach project bootstrap CLI commands to the Flask app instance."""
    app.cli.add_command(seed_roles_command)
    app.cli.add_command(create_admin_command)
