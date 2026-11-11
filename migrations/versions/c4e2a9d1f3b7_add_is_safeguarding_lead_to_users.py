"""add is_safeguarding_lead to users

Revision ID: c4e2a9d1f3b7
Revises: b31aa2f4d5cc
Create Date: 2026-11-11 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4e2a9d1f3b7'
down_revision = 'b31aa2f4d5cc'
branch_labels = None
depends_on = None


def upgrade():
    # server_default fills existing rows with false, so every current account starts
    # without the safeguarding-lead duty (fail closed).
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('is_safeguarding_lead', sa.Boolean(), server_default=sa.false(), nullable=False)
        )


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('is_safeguarding_lead')
