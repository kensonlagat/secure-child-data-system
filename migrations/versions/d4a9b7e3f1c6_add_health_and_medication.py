"""add health entries, medication schedules and the administration log (#57)

Revision ID: d4a9b7e3f1c6
Revises: c3f8a6d2e9b4
Create Date: 2026-11-17 23:00:00.000000

Health text holds AES-GCM ciphertext. health_entries and medication_administrations are
append-only: on PostgreSQL this migration revokes UPDATE, DELETE and TRUNCATE on them from
every non-owner role straight away, and `flask setup-db-roles` keeps it so.
Medication schedules can be stopped, so they keep the default UPDATE.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd4a9b7e3f1c6'
down_revision = 'c3f8a6d2e9b4'
branch_labels = None
depends_on = None

APPEND_ONLY = ("health_entries", "medication_administrations")
REVOKE_WRITES_FROM_NON_OWNERS = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = '{table}'
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.{table} FROM %I', grantee_name);
    END LOOP;
END $$;
"""


def upgrade():
    op.create_table(
        'health_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('entry_type', sa.String(length=20), nullable=False),
        sa.Column('entry_at', sa.DateTime(), nullable=False),
        sa.Column('details', sa.LargeBinary(), nullable=False),
        sa.Column('recorded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_health_entries_child_record_id', 'health_entries', ['child_record_id'])
    op.create_table(
        'medication_schedules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('medicine', sa.LargeBinary(), nullable=False),
        sa.Column('dose', sa.LargeBinary(), nullable=False),
        sa.Column('daily_times', sa.String(length=60), nullable=False),
        sa.Column('start_date', sa.Date(), nullable=False),
        sa.Column('end_date', sa.Date(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('stopped_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('stopped_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_medication_schedules_child_record_id', 'medication_schedules', ['child_record_id'])
    op.create_table(
        'medication_administrations',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('schedule_id', sa.Integer(), sa.ForeignKey('medication_schedules.id'), nullable=False),
        sa.Column('scheduled_for', sa.DateTime(), nullable=False),
        sa.Column('outcome', sa.String(length=10), nullable=False),
        sa.Column('given_at', sa.DateTime(), nullable=True),
        sa.Column('note', sa.LargeBinary(), nullable=True),
        sa.Column('recorded_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_medication_administrations_schedule_id', 'medication_administrations', ['schedule_id'])
    if op.get_bind().dialect.name == 'postgresql':
        for table in APPEND_ONLY:
            op.execute(REVOKE_WRITES_FROM_NON_OWNERS.format(table=table))


def downgrade():
    op.drop_index('ix_medication_administrations_schedule_id', table_name='medication_administrations')
    op.drop_table('medication_administrations')
    op.drop_index('ix_medication_schedules_child_record_id', table_name='medication_schedules')
    op.drop_table('medication_schedules')
    op.drop_index('ix_health_entries_child_record_id', table_name='health_entries')
    op.drop_table('health_entries')
