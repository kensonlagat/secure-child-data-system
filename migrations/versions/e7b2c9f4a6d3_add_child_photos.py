"""add child photos (#87)

Revision ID: e7b2c9f4a6d3
Revises: d1a6b3c8f5e2
Create Date: 2026-11-18 13:00:00.000000

Photos hold AES-256-GCM ciphertext. child_photos is append-only (rows are written once,
complete): on PostgreSQL this migration revokes UPDATE, DELETE and TRUNCATE from every
non-owner role straight away, and `flask setup-db-roles` keeps it so.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e7b2c9f4a6d3'
down_revision = 'd1a6b3c8f5e2'
branch_labels = None
depends_on = None

REVOKE = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'child_photos'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.child_photos FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'child_photos',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('blob_id', sa.String(length=32), nullable=False, unique=True),
        sa.Column('content_type', sa.String(length=20), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('uploaded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_child_photos_child_record_id', 'child_photos', ['child_record_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(REVOKE)


def downgrade():
    op.drop_index('ix_child_photos_child_record_id', table_name='child_photos')
    op.drop_table('child_photos')
