"""make audit user nullable and track attempted identifier

Revision ID: b31aa2f4d5cc
Revises: 8f4c2d1b7a91
Create Date: 2026-10-01 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b31aa2f4d5cc'
down_revision = '8f4c2d1b7a91'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('audit_log_entries', 'user_id', existing_type=sa.Integer(), nullable=True)
    op.add_column('audit_log_entries', sa.Column('attempted_identifier', sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column('audit_log_entries', 'attempted_identifier')
    op.alter_column('audit_log_entries', 'user_id', existing_type=sa.Integer(), nullable=False)