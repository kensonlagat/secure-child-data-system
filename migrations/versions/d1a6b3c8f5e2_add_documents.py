"""add encrypted document storage (#66)

Revision ID: d1a6b3c8f5e2
Revises: c9f4a1d7e2b5
Create Date: 2026-11-18 11:00:00.000000

document_blobs holds AES-256-GCM ciphertext (document id bound as associated data) and is
append-only. On documents the app role may update only is_deleted and deleted_at (soft,
OTP-gated deletion). On PostgreSQL this migration applies both rules straight away for every
non-owner role; `flask setup-db-roles` keeps them (APPEND_ONLY_TABLES, COLUMN_UPDATE_TABLES).
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd1a6b3c8f5e2'
down_revision = 'c9f4a1d7e2b5'
branch_labels = None
depends_on = None

RESTRICT = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name IN ('documents', 'document_blobs')
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.document_blobs FROM %I', grantee_name);
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.documents FROM %I', grantee_name);
        EXECUTE format('GRANT UPDATE (is_deleted, deleted_at) ON public.documents TO %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'documents',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('document_type', sa.String(length=30), nullable=False),
        sa.Column('original_filename', sa.LargeBinary(), nullable=False),
        sa.Column('content_type', sa.String(length=30), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('uploaded_at', sa.DateTime(), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_documents_child_record_id', 'documents', ['child_record_id'])
    op.create_table(
        'document_blobs',
        sa.Column('document_id', sa.Integer(), sa.ForeignKey('documents.id'), primary_key=True),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
    )
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(RESTRICT)


def downgrade():
    op.drop_table('document_blobs')
    op.drop_index('ix_documents_child_record_id', table_name='documents')
    op.drop_table('documents')
