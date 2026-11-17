"""pickup collectors: pending, confirmed, rejected status (#112)

Revision ID: f3d6b9a1c8e2
Revises: e9c2a7b5d4f1
Create Date: 2026-11-17 15:00:00.000000

Collectors added by a teacher start `pending` and only `active` ones appear at the gate.
Existing rows: active stay `active`, revoked become `revoked`. On PostgreSQL the roles that
may already update the revoke columns also get UPDATE on the new status and decision
columns (column-level only; collector details stay fixed). `flask setup-db-roles` keeps it so.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f3d6b9a1c8e2'
down_revision = 'e9c2a7b5d4f1'
branch_labels = None
depends_on = None

GRANT_DECISION_COLUMNS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.column_privileges
        WHERE table_schema = 'public' AND table_name = 'authorised_collectors'
          AND column_name = 'is_active' AND privilege_type = 'UPDATE'
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('GRANT UPDATE (status, decided_by, decided_at) ON public.authorised_collectors TO %I',
                       grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    with op.batch_alter_table('authorised_collectors') as batch:
        batch.add_column(sa.Column('status', sa.String(length=10), nullable=False, server_default='active'))
        batch.add_column(sa.Column('decided_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True))
        batch.add_column(sa.Column('decided_at', sa.DateTime(), nullable=True))
    op.execute(sa.text("UPDATE authorised_collectors SET status = 'revoked' WHERE is_active = false"))
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(GRANT_DECISION_COLUMNS)


def downgrade():
    with op.batch_alter_table('authorised_collectors') as batch:
        batch.drop_column('decided_at')
        batch.drop_column('decided_by')
        batch.drop_column('status')
