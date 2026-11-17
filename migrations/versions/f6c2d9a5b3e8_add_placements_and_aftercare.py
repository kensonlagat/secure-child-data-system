"""add placements and aftercare follow-ups (#59)

Revision ID: f6c2d9a5b3e8
Revises: e5b1c8f4a2d7
Create Date: 2026-11-18 03:00:00.000000

Destination and follow-up notes hold AES-GCM ciphertext. placements is append-only: on
PostgreSQL this migration revokes UPDATE, DELETE and TRUNCATE on it from every non-owner
role straight away, and `flask setup-db-roles` keeps it so. Follow-ups are marked done
later, so aftercare_followups keeps the default UPDATE. Nothing here touches legal_status.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f6c2d9a5b3e8'
down_revision = 'e5b1c8f4a2d7'
branch_labels = None
depends_on = None

REVOKE_WRITES_FROM_NON_OWNERS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'placements'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.placements FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'placements',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('outcome', sa.String(length=30), nullable=False),
        sa.Column('exit_date', sa.Date(), nullable=False),
        sa.Column('destination_notes', sa.LargeBinary(), nullable=True),
        sa.Column('recorded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_placements_child_record_id', 'placements', ['child_record_id'])
    op.create_table(
        'aftercare_followups',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('placement_id', sa.Integer(), sa.ForeignKey('placements.id'), nullable=False),
        sa.Column('due_date', sa.Date(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('completed_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('notes', sa.LargeBinary(), nullable=True),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_aftercare_followups_placement_id', 'aftercare_followups', ['placement_id'])
    op.create_index('ix_aftercare_followups_due_date', 'aftercare_followups', ['due_date'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(REVOKE_WRITES_FROM_NON_OWNERS)


def downgrade():
    op.drop_index('ix_aftercare_followups_due_date', table_name='aftercare_followups')
    op.drop_index('ix_aftercare_followups_placement_id', table_name='aftercare_followups')
    op.drop_table('aftercare_followups')
    op.drop_index('ix_placements_child_record_id', table_name='placements')
    op.drop_table('placements')
