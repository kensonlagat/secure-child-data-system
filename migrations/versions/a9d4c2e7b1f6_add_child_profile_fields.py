"""add child profile fields: gender, birth certificate, learner UPI, allergies (#49a)

Revision ID: a9d4c2e7b1f6
Revises: f5b2d8e1a7c3
Create Date: 2026-11-17 01:00:00.000000

All columns are nullable with no backfill: empty means "not recorded". The three sensitive
columns hold AES-GCM ciphertext written by IntegrityCheckedEncryptedType (bytea, the same
storage as the other encrypted columns). Downgrading drops the columns and the data in them.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a9d4c2e7b1f6'
down_revision = 'f5b2d8e1a7c3'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('child_records') as batch:
        batch.add_column(sa.Column('gender', sa.String(length=20), nullable=True))
        batch.add_column(sa.Column('birth_certificate_number', sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column('learner_upi', sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column('allergies', sa.LargeBinary(), nullable=True))


def downgrade():
    # Drops these columns and their data.
    with op.batch_alter_table('child_records') as batch:
        batch.drop_column('allergies')
        batch.drop_column('learner_upi')
        batch.drop_column('birth_certificate_number')
        batch.drop_column('gender')
