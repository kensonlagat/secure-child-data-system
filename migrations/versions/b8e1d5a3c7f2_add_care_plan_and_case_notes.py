"""add care plan goals and case notes (#55)

Revision ID: b8e1d5a3c7f2
Revises: a2c7e4f9b6d1
Create Date: 2026-11-17 19:00:00.000000

Goal text, note bodies and legal summaries hold AES-GCM ciphertext. Goals can be updated
(status and review date). case_notes is append-only: on PostgreSQL this migration revokes
UPDATE, DELETE and TRUNCATE on it from every non-owner role straight away, and
`flask setup-db-roles` keeps it so (APPEND_ONLY_TABLES).
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b8e1d5a3c7f2'
down_revision = 'a2c7e4f9b6d1'
branch_labels = None
depends_on = None

REVOKE_WRITES_FROM_NON_OWNERS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'case_notes'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.case_notes FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'care_plan_goals',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('goal', sa.LargeBinary(), nullable=False),
        sa.Column('review_date', sa.Date(), nullable=False),
        sa.Column('status', sa.String(length=15), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_care_plan_goals_child_record_id', 'care_plan_goals', ['child_record_id'])
    op.create_table(
        'case_notes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('note_date', sa.Date(), nullable=False),
        sa.Column('category', sa.String(length=15), nullable=False),
        sa.Column('body', sa.LargeBinary(), nullable=False),
        sa.Column('legal_summary', sa.LargeBinary(), nullable=True),
        sa.Column('author_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_case_notes_child_record_id', 'case_notes', ['child_record_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(REVOKE_WRITES_FROM_NON_OWNERS)


def downgrade():
    op.drop_index('ix_case_notes_child_record_id', table_name='case_notes')
    op.drop_table('case_notes')
    op.drop_index('ix_care_plan_goals_child_record_id', table_name='care_plan_goals')
    op.drop_table('care_plan_goals')
