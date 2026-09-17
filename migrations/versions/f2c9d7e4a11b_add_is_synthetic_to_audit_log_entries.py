"""add is_synthetic to audit log entries

Revision ID: f2c9d7e4a11b
Revises: c868103e9ed1
Create Date: 2026-09-17 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f2c9d7e4a11b'
down_revision = 'c868103e9ed1'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'audit_log_entries',
        sa.Column('is_synthetic', sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade():
    op.drop_column('audit_log_entries', 'is_synthetic')