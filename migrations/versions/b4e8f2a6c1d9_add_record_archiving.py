"""add leaving, transfer and archiving columns to child records (#64)

Revision ID: b4e8f2a6c1d9
Revises: a7d3e1b8c5f9
Create Date: 2026-11-18 07:00:00.000000

Archived records stay in the table (no hard delete); is_archived hides them from every
day-to-day role. Existing rows are not archived (server default false).
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b4e8f2a6c1d9'
down_revision = 'a7d3e1b8c5f9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('child_records') as batch:
        batch.add_column(sa.Column('is_archived', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column('archived_at', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('archived_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True))
        batch.add_column(sa.Column('leave_reason', sa.String(length=30), nullable=True))
        batch.add_column(sa.Column('leave_date', sa.Date(), nullable=True))


def downgrade():
    with op.batch_alter_table('child_records') as batch:
        batch.drop_column('leave_date')
        batch.drop_column('leave_reason')
        batch.drop_column('archived_by')
        batch.drop_column('archived_at')
        batch.drop_column('is_archived')
