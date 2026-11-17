"""add the parent portal: login_phone and guardian_links (#67)

Revision ID: a9d4b6e2c1f8
Revises: f8c3a5d1e9b7
Create Date: 2026-11-18 18:00:00.000000

- users.login_phone: nullable, unique, used only by parent accounts (D67.1). users.email becomes
  nullable because parent accounts have none; a check keeps every account with one or the other.
- guardian_links: one row per child and parent, never deleted. The identity check records the
  document TYPE only; there is deliberately no column for a document number.
- On PostgreSQL non-owner roles lose UPDATE, DELETE and TRUNCATE on guardian_links and get
  UPDATE back on the status columns only (COLUMN_UPDATE_TABLES keeps this on setup-db-roles).
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a9d4b6e2c1f8'
down_revision = 'f8c3a5d1e9b7'
branch_labels = None
depends_on = None

RESTRICT = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'guardian_links'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.guardian_links FROM %I', grantee_name);
        EXECUTE format('GRANT UPDATE (status, verified_by, verified_at, revoked_by, revoked_at) '
                       'ON public.guardian_links TO %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('login_phone', sa.String(length=20), nullable=True))
        batch.alter_column('email', existing_type=sa.String(length=120), nullable=True)
        batch.create_unique_constraint('uq_users_login_phone', ['login_phone'])
        batch.create_check_constraint('ck_users_email_or_login_phone',
                                      'email IS NOT NULL OR login_phone IS NOT NULL')
    op.create_table(
        'guardian_links',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('guardian_user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('relationship', sa.String(length=20), nullable=False),
        sa.Column('identity_document_type', sa.String(length=30), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False, server_default='pending'),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('verified_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint("status IN ('pending', 'active', 'revoked')", name='ck_guardian_link_status'),
        sa.CheckConstraint("relationship IN ('mother', 'father', 'guardian', 'other')",
                           name='ck_guardian_link_relationship'),
        sa.CheckConstraint("identity_document_type IN ('national_id', 'passport', 'birth_certificate', "
                           "'alien_id', 'other')", name='ck_guardian_link_document_type'),
    )
    op.create_index('ix_guardian_links_child_record_id', 'guardian_links', ['child_record_id'])
    op.create_index('ix_guardian_links_guardian_user_id', 'guardian_links', ['guardian_user_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(RESTRICT)


def downgrade():
    op.drop_index('ix_guardian_links_guardian_user_id', table_name='guardian_links')
    op.drop_index('ix_guardian_links_child_record_id', table_name='guardian_links')
    op.drop_table('guardian_links')
    with op.batch_alter_table('users') as batch:
        batch.drop_constraint('ck_users_email_or_login_phone', type_='check')
        batch.drop_constraint('uq_users_login_phone', type_='unique')
        batch.alter_column('email', existing_type=sa.String(length=120), nullable=False)
        batch.drop_column('login_phone')
