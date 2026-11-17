"""add court hearings (#56)

Revision ID: c3f8a6d2e9b4
Revises: b8e1d5a3c7f2
Create Date: 2026-11-17 21:00:00.000000

The case reference and outcome hold AES-GCM ciphertext. Hearings are updated after they
happen (every change audited), so the app role keeps the default SELECT, INSERT, UPDATE.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c3f8a6d2e9b4'
down_revision = 'b8e1d5a3c7f2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'court_hearings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('hearing_at', sa.DateTime(), nullable=False),
        sa.Column('court', sa.String(length=120), nullable=False),
        sa.Column('case_reference', sa.LargeBinary(), nullable=False),
        sa.Column('outcome', sa.LargeBinary(), nullable=True),
        sa.Column('next_date', sa.Date(), nullable=True),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_court_hearings_child_record_id', 'court_hearings', ['child_record_id'])
    op.create_index('ix_court_hearings_hearing_at', 'court_hearings', ['hearing_at'])


def downgrade():
    op.drop_index('ix_court_hearings_hearing_at', table_name='court_hearings')
    op.drop_index('ix_court_hearings_child_record_id', table_name='court_hearings')
    op.drop_table('court_hearings')
