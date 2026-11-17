"""add export requests (#65)

Revision ID: c9f4a1d7e2b5
Revises: b4e8f2a6c1d9
Create Date: 2026-11-18 09:00:00.000000

Holds only what an export will contain (type, target id, column names and their hash),
never the exported data. Requests move from pending to completed (UPDATE), never deleted.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c9f4a1d7e2b5'
down_revision = 'b4e8f2a6c1d9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'export_requests',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('export_type', sa.String(length=20), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('columns', sa.String(length=500), nullable=False),
        sa.Column('params_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_export_requests_user_id', 'export_requests', ['user_id'])


def downgrade():
    op.drop_index('ix_export_requests_user_id', table_name='export_requests')
    op.drop_table('export_requests')
