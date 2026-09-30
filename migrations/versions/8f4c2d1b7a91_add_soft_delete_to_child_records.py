"""add soft delete to child records

Revision ID: 8f4c2d1b7a91
Revises: 7b5ab018e9cf
Create Date: 2026-09-30 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8f4c2d1b7a91'
down_revision = '7b5ab018e9cf'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'child_records',
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        'child_records',
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_column('child_records', 'deleted_at')
    op.drop_column('child_records', 'is_deleted')