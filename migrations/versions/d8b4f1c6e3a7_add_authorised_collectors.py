"""add authorised collectors for the pickup list (#51)

Revision ID: d8b4f1c6e3a7
Revises: c5a1e8d3f2b9
Create Date: 2026-11-17 07:00:00.000000

Collector details are fixed once written: on PostgreSQL this migration replaces the
default table-wide UPDATE with a column-level UPDATE on the revoke columns only, and
revokes DELETE and TRUNCATE, for every non-owner role. `flask setup-db-roles` keeps it so
(COLUMN_UPDATE_TABLES in app/db_roles.py).
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd8b4f1c6e3a7'
down_revision = 'c5a1e8d3f2b9'
branch_labels = None
depends_on = None

RESTRICT_UPDATES = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'authorised_collectors'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.authorised_collectors FROM %I', grantee_name);
        EXECUTE format('GRANT UPDATE (is_active, revoked_by, revoked_at) ON public.authorised_collectors TO %I',
                       grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'authorised_collectors',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('full_name', sa.LargeBinary(), nullable=False),           # AES-GCM ciphertext
        sa.Column('relationship', sa.String(length=20), nullable=False),
        sa.Column('phone_number', sa.LargeBinary(), nullable=False),        # AES-GCM ciphertext
        sa.Column('national_id_number', sa.LargeBinary(), nullable=False),  # AES-GCM ciphertext
        sa.Column('added_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('added_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('revoked_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_authorised_collectors_child_record_id', 'authorised_collectors', ['child_record_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(RESTRICT_UPDATES)


def downgrade():
    op.drop_index('ix_authorised_collectors_child_record_id', table_name='authorised_collectors')
    op.drop_table('authorised_collectors')
