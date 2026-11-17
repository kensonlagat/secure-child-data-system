"""add missing child alerts (#60)

Revision ID: a7d3e1b8c5f9
Revises: f6c2d9a5b3e8
Create Date: 2026-11-18 05:00:00.000000

Circumstances, actions taken and resolution notes hold AES-GCM ciphertext. Alerts are
updated (actions, resolution), every change audited with timestamps, so the app role keeps
the default SELECT, INSERT, UPDATE (never DELETE).
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a7d3e1b8c5f9'
down_revision = 'f6c2d9a5b3e8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'missing_child_alerts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('circumstances', sa.LargeBinary(), nullable=False),
        sa.Column('actions_taken', sa.LargeBinary(), nullable=True),
        sa.Column('raised_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('raised_at', sa.DateTime(), nullable=False),
        sa.Column('found_at', sa.DateTime(), nullable=True),
        sa.Column('resolution_notes', sa.LargeBinary(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_missing_child_alerts_child_record_id', 'missing_child_alerts', ['child_record_id'])


def downgrade():
    op.drop_index('ix_missing_child_alerts_child_record_id', table_name='missing_child_alerts')
    op.drop_table('missing_child_alerts')
