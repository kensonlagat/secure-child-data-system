"""add restricted function for purging synthetic audit rows

Revision ID: d7f1b3c5e9a2
Revises: c4e2a9d1f3b7
Create Date: 2026-11-11 18:00:00.000000

The web app's database role has no DELETE on audit_log_entries (#72). The one sanctioned
exception to the insert-only audit log, `flask clear-synthetic-audit-data`, goes through
this SECURITY DEFINER function instead. It runs with its owner's rights but can only ever
delete rows marked is_synthetic (and the anomaly alerts that point at them).
PostgreSQL only; other dialects (the SQLite test database) skip it.
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'd7f1b3c5e9a2'
down_revision = 'c4e2a9d1f3b7'
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION purge_synthetic_audit_entries()
        RETURNS integer
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
        DECLARE
            deleted_count integer;
        BEGIN
            DELETE FROM anomaly_alerts
            WHERE audit_log_entry_id IN (
                SELECT id FROM audit_log_entries WHERE is_synthetic IS TRUE
            );
            DELETE FROM audit_log_entries WHERE is_synthetic IS TRUE;
            GET DIAGNOSTICS deleted_count = ROW_COUNT;
            RETURN deleted_count;
        END;
        $$;
        """
    )
    # Nobody may call it by default; `flask setup-db-roles` grants EXECUTE to the app role.
    op.execute("REVOKE ALL ON FUNCTION purge_synthetic_audit_entries() FROM PUBLIC")


def downgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("DROP FUNCTION IF EXISTS purge_synthetic_audit_entries()")
