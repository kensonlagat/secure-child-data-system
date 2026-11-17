"""add intake records for children's-home admissions (#54)

Revision ID: a2c7e4f9b6d1
Revises: f3d6b9a1c8e2
Create Date: 2026-11-17 17:00:00.000000

One intake per child (unique child_record_id). The placement reason, committal order
reference and children's officer columns hold AES-GCM ciphertext. Intakes can be
corrected (every change audited), so the app role keeps the default SELECT, INSERT, UPDATE.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a2c7e4f9b6d1'
down_revision = 'f3d6b9a1c8e2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'intake_records',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False, unique=True),
        sa.Column('referral_source', sa.String(length=30), nullable=False),
        sa.Column('admission_date', sa.Date(), nullable=False),
        sa.Column('placement_reason', sa.LargeBinary(), nullable=False),
        sa.Column('committal_order_reference', sa.LargeBinary(), nullable=True),
        sa.Column('childrens_officer', sa.LargeBinary(), nullable=True),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table('intake_records')
