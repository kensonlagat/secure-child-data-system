"""add consent records (#63)

Revision ID: b7e3f9a2c4d8
Revises: a9d4c2e7b1f6
Create Date: 2026-11-17 03:00:00.000000

Append-only: the app role may SELECT and INSERT but never UPDATE or DELETE. Default
privileges would grant UPDATE to the app role as soon as the owner creates the table, so
on PostgreSQL this migration revokes UPDATE and DELETE from every role except the owner
straight away (no window), and `flask setup-db-roles` applies the same rule afterwards.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b7e3f9a2c4d8'
down_revision = 'a9d4c2e7b1f6'
branch_labels = None
depends_on = None

REVOKE_WRITES_FROM_NON_OWNERS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = '{table}'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.{table} FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'consent_records',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('consent_type', sa.String(length=30), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('effective_date', sa.Date(), nullable=False),
        sa.Column('guardian_name', sa.LargeBinary(), nullable=False),  # AES-GCM ciphertext
        sa.Column('recorded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_consent_records_child_record_id', 'consent_records', ['child_record_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(REVOKE_WRITES_FROM_NON_OWNERS.format(table='consent_records'))


def downgrade():
    op.drop_index('ix_consent_records_child_record_id', table_name='consent_records')
    op.drop_table('consent_records')
