"""add family visits and family tracing (#58)

Revision ID: e5b1c8f4a2d7
Revises: d4a9b7e3f1c6
Create Date: 2026-11-18 01:00:00.000000

Visitor names and notes hold AES-GCM ciphertext. family_visits is append-only: on
PostgreSQL this migration revokes UPDATE, DELETE and TRUNCATE on it from every non-owner
role straight away, and `flask setup-db-roles` keeps it so. family_tracing (one status per
child) keeps the default UPDATE.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e5b1c8f4a2d7'
down_revision = 'd4a9b7e3f1c6'
branch_labels = None
depends_on = None

REVOKE_WRITES_FROM_NON_OWNERS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'family_visits'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.family_visits FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'family_visits',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('visit_at', sa.DateTime(), nullable=False),
        sa.Column('visitor_name', sa.LargeBinary(), nullable=False),
        sa.Column('relationship', sa.String(length=20), nullable=False),
        sa.Column('supervised', sa.Boolean(), nullable=False),
        sa.Column('notes', sa.LargeBinary(), nullable=True),
        sa.Column('recorded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_family_visits_child_record_id', 'family_visits', ['child_record_id'])
    op.create_table(
        'family_tracing',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False, unique=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(REVOKE_WRITES_FROM_NON_OWNERS)


def downgrade():
    op.drop_table('family_tracing')
    op.drop_index('ix_family_visits_child_record_id', table_name='family_visits')
    op.drop_table('family_visits')
