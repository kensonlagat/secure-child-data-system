"""add attendance registers, marks, corrections and absence alerts (#50)

Revision ID: c5a1e8d3f2b9
Revises: b7e3f9a2c4d8
Create Date: 2026-11-17 05:00:00.000000

attendance_corrections and absence_alerts are append-only: on PostgreSQL this migration
revokes UPDATE, DELETE and TRUNCATE on them from every non-owner role straight away (the
default privileges would otherwise grant UPDATE), and `flask setup-db-roles` keeps it so.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c5a1e8d3f2b9'
down_revision = 'b7e3f9a2c4d8'
branch_labels = None
depends_on = None

APPEND_ONLY = ("attendance_corrections", "absence_alerts")
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
        'attendance_registers',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('class_id', sa.Integer(), sa.ForeignKey('school_classes.id'), nullable=False),
        sa.Column('register_date', sa.Date(), nullable=False),
        sa.Column('taken_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('taken_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('class_id', 'register_date', name='uq_attendance_register_class_date'),
    )
    op.create_index('ix_attendance_registers_class_id', 'attendance_registers', ['class_id'])
    op.create_table(
        'attendance_marks',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('register_id', sa.Integer(), sa.ForeignKey('attendance_registers.id'), nullable=False),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('register_id', 'child_record_id', name='uq_attendance_mark_child'),
    )
    op.create_index('ix_attendance_marks_register_id', 'attendance_marks', ['register_id'])
    op.create_index('ix_attendance_marks_child_record_id', 'attendance_marks', ['child_record_id'])
    op.create_table(
        'attendance_corrections',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('mark_id', sa.Integer(), sa.ForeignKey('attendance_marks.id'), nullable=False),
        sa.Column('old_status', sa.String(length=10), nullable=False),
        sa.Column('new_status', sa.String(length=10), nullable=False),
        sa.Column('reason', sa.LargeBinary(), nullable=False),  # AES-GCM ciphertext
        sa.Column('corrected_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('corrected_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_attendance_corrections_mark_id', 'attendance_corrections', ['mark_id'])
    op.create_table(
        'absence_alerts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('absences', sa.Integer(), nullable=False),
        sa.Column('window_days', sa.Integer(), nullable=False),
        sa.Column('outcome', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_absence_alerts_child_record_id', 'absence_alerts', ['child_record_id'])
    if op.get_bind().dialect.name == 'postgresql':
        for table in APPEND_ONLY:
            op.execute(REVOKE_WRITES_FROM_NON_OWNERS.format(table=table))


def downgrade():
    op.drop_index('ix_absence_alerts_child_record_id', table_name='absence_alerts')
    op.drop_table('absence_alerts')
    op.drop_index('ix_attendance_corrections_mark_id', table_name='attendance_corrections')
    op.drop_table('attendance_corrections')
    op.drop_index('ix_attendance_marks_child_record_id', table_name='attendance_marks')
    op.drop_index('ix_attendance_marks_register_id', table_name='attendance_marks')
    op.drop_table('attendance_marks')
    op.drop_index('ix_attendance_registers_class_id', table_name='attendance_registers')
    op.drop_table('attendance_registers')
