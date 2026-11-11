"""Least-privilege database roles (#72).

The PostgreSQL behaviour (grants, refused UPDATE/DELETE on the audit log, the restricted
purge function, migrations as owner) is proven end to end with
`flask setup-db-roles` + `flask check-db-privileges` on a real database; see the PR.
These tests cover the parts that run without PostgreSQL.
"""

from datetime import datetime

import pytest

from app import create_app, db
from app.db_roles import setup_roles, validate_role_name
from app.models.audit_log import AuditLogEntry


@pytest.mark.parametrize("name", ["cds_app", "cds_owner", "_x", "a1_b2"])
def test_valid_role_names(name):
    assert validate_role_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "CDS_APP", "cds-app", "cds app", 'cds"; DROP ROLE postgres; --', "1cds", "a" * 64, None],
)
def test_invalid_role_names_are_rejected_before_any_sql(name):
    with pytest.raises(ValueError):
        validate_role_name(name)


def test_owner_and_app_roles_must_differ():
    with pytest.raises(ValueError):
        setup_roles("postgresql://unused", "cds_same", "cds_same")


def test_injection_in_role_name_never_reaches_the_database():
    # Validation happens before connecting, so a bad name fails without a database.
    with pytest.raises(ValueError):
        setup_roles("postgresql://unused", "cds_owner", "x; DROP TABLE users")


def test_libpq_dsn_drops_the_driver_suffix():
    from app.cli import _libpq_dsn

    assert _libpq_dsn("postgresql+psycopg2://u@h/db") == "postgresql://u@h/db"
    assert _libpq_dsn("postgresql://u@h/db") == "postgresql://u@h/db"


def test_clear_synthetic_audit_data_keeps_real_rows():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        for synthetic in (True, True, False):
            db.session.add(AuditLogEntry(action="login", attempted_identifier="x",
                                         is_synthetic=synthetic, timestamp=datetime.utcnow()))
        db.session.commit()

    with app.app_context():  # the real `flask` command pushes this itself
        result = app.test_cli_runner().invoke(args=["clear-synthetic-audit-data"])

    assert result.exit_code == 0
    assert "Deleted 2 synthetic audit rows." in result.output
    with app.app_context():
        assert AuditLogEntry.query.filter_by(is_synthetic=True).count() == 0
        assert AuditLogEntry.query.filter_by(is_synthetic=False).count() == 1
        db.drop_all()
