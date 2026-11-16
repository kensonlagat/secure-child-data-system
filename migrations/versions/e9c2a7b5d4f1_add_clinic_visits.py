"""add clinic visits (#52)

Revision ID: e9c2a7b5d4f1
Revises: d8b4f1c6e3a7
Create Date: 2026-11-17 09:00:00.000000

Clinical text columns hold AES-GCM ciphertext. Append-only: on PostgreSQL this migration
revokes UPDATE, DELETE and TRUNCATE from every non-owner role straight away, and
`flask setup-db-roles` keeps it so (APPEND_ONLY_TABLES).
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e9c2a7b5d4f1'
down_revision = 'd8b4f1c6e3a7'
branch_labels = None
depends_on = None

REVOKE_WRITES_FROM_NON_OWNERS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'clinic_visits'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.clinic_visits FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'clinic_visits',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('visited_at', sa.DateTime(), nullable=False),
        sa.Column('complaint', sa.LargeBinary(), nullable=False),
        sa.Column('treatment', sa.LargeBinary(), nullable=False),
        sa.Column('medicines_given', sa.LargeBinary(), nullable=True),
        sa.Column('follow_up', sa.LargeBinary(), nullable=True),
        sa.Column('immunisation', sa.LargeBinary(), nullable=True),
        sa.Column('recorded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_clinic_visits_child_record_id', 'clinic_visits', ['child_record_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(REVOKE_WRITES_FROM_NON_OWNERS)


def downgrade():
    op.drop_index('ix_clinic_visits_child_record_id', table_name='clinic_visits')
    op.drop_table('clinic_visits')
