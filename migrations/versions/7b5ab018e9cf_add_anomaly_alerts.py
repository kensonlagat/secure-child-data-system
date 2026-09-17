"""add anomaly alerts

Revision ID: 7b5ab018e9cf
Revises: f2c9d7e4a11b
Create Date: 2026-09-17 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7b5ab018e9cf'
down_revision = 'f2c9d7e4a11b'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'anomaly_alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('audit_log_entry_id', sa.Integer(), nullable=False),
        sa.Column('role_name', sa.String(length=50), nullable=False),
        sa.Column('anomaly_score', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_log_entry_id'], ['audit_log_entries.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('audit_log_entry_id'),
    )


def downgrade():
    op.drop_table('anomaly_alerts')