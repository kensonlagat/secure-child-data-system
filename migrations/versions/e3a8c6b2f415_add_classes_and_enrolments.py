"""add classes, teacher assignments and enrolments (#48)

Revision ID: e3a8c6b2f415
Revises: d7f1b3c5e9a2
Create Date: 2026-11-12 09:00:00.000000

Teacher scoping moves from the free-text users.assigned_class / child_records.class_assigned
columns to these tables. The backfill maps every existing non-empty value without loss:
"Grade 6A" becomes class "Grade 6" stream "A"; an unparseable value keeps the whole text as
the class name with an empty stream. Every school record with a class gets one current
enrolment (deleted records included, so their history survives), and every teacher gets an
assignment to the matching class. The legacy columns are left untouched (read-only for one
release, dropped later). Downgrade drops only the new tables.
"""
import re
from datetime import date, datetime

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e3a8c6b2f415'
down_revision = 'd7f1b3c5e9a2'
branch_labels = None
depends_on = None

MIGRATION_ACADEMIC_YEAR = 2026  # D48.1
_LABEL_PATTERN = re.compile(r"^(.*\d)\s*([A-Za-z])$")


def _split(label):
    # A frozen copy of split_class_label() as it was when this migration was written.
    label = (label or "").strip()
    match = _LABEL_PATTERN.match(label)
    if match:
        return match.group(1).strip(), match.group(2).upper()
    return label, ""


def upgrade():
    op.create_table(
        'school_classes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('stream', sa.String(length=10), nullable=False, server_default=''),
        sa.Column('academic_year', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('name', 'stream', 'academic_year', name='uq_school_classes_name_stream_year'),
    )
    op.create_table(
        'class_teacher_assignments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('class_id', sa.Integer(), sa.ForeignKey('school_classes.id'), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('assigned_at', sa.DateTime(), nullable=False),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_class_teacher_assignments_class_id', 'class_teacher_assignments', ['class_id'])
    op.create_index('ix_class_teacher_assignments_user_id', 'class_teacher_assignments', ['user_id'])
    op.create_table(
        'enrolments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('class_id', sa.Integer(), sa.ForeignKey('school_classes.id'), nullable=False),
        sa.Column('started_on', sa.Date(), nullable=False),
        sa.Column('ended_on', sa.Date(), nullable=True),
        sa.Column('reason', sa.String(length=20), nullable=False),
        sa.Column('end_reason', sa.String(length=20), nullable=True),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
    )
    op.create_index('ix_enrolments_child_record_id', 'enrolments', ['child_record_id'])
    op.create_index('ix_enrolments_class_id', 'enrolments', ['class_id'])
    # Backstop for the application check: one current enrolment per child.
    op.create_index('uq_enrolments_one_current', 'enrolments', ['child_record_id'], unique=True,
                    postgresql_where=sa.text('ended_on IS NULL'), sqlite_where=sa.text('ended_on IS NULL'))

    _backfill()


def _backfill():
    conn = op.get_bind()
    now = datetime.utcnow()
    children = conn.execute(sa.text(
        "SELECT id, class_assigned, created_at FROM child_records "
        "WHERE institution_mode = 'school' AND class_assigned IS NOT NULL AND TRIM(class_assigned) <> ''"
    )).all()
    teachers = conn.execute(sa.text(
        "SELECT u.id, u.assigned_class FROM users u JOIN roles r ON r.id = u.role_id "
        "WHERE r.name = 'teacher' AND u.assigned_class IS NOT NULL AND TRIM(u.assigned_class) <> ''"
    )).all()

    classes = sa.table('school_classes', sa.column('id'), sa.column('name'), sa.column('stream'),
                       sa.column('academic_year'), sa.column('is_active'), sa.column('created_at'))
    class_ids = {}
    for label in sorted({row.class_assigned for row in children} | {row.assigned_class for row in teachers}):
        key = _split(label)
        if key in class_ids:
            continue
        conn.execute(classes.insert().values(name=key[0], stream=key[1], academic_year=MIGRATION_ACADEMIC_YEAR,
                                             is_active=True, created_at=now))
        class_ids[key] = conn.execute(sa.text(
            "SELECT id FROM school_classes WHERE name = :n AND stream = :s AND academic_year = :y"
        ), {"n": key[0], "s": key[1], "y": MIGRATION_ACADEMIC_YEAR}).scalar_one()

    enrolments = sa.table('enrolments', sa.column('child_record_id'), sa.column('class_id'),
                          sa.column('started_on'), sa.column('reason'))
    for row in children:
        created = row.created_at  # a datetime on PostgreSQL, text on SQLite
        if isinstance(created, datetime):
            started = created.date()
        elif isinstance(created, date):
            started = created
        elif isinstance(created, str) and created:
            started = date.fromisoformat(created[:10])
        else:
            started = date.today()
        conn.execute(enrolments.insert().values(child_record_id=row.id, class_id=class_ids[_split(row.class_assigned)],
                                                started_on=started, reason='migrated'))

    assignments = sa.table('class_teacher_assignments', sa.column('class_id'), sa.column('user_id'),
                           sa.column('assigned_at'))
    for row in teachers:
        conn.execute(assignments.insert().values(class_id=class_ids[_split(row.assigned_class)], user_id=row.id,
                                                 assigned_at=now))

    # Every legacy value must be mapped, or the migration stops (and rolls back).
    mapped = conn.execute(sa.text("SELECT COUNT(*) FROM enrolments")).scalar_one()
    if mapped != len(children):
        raise RuntimeError(f"Backfill mapped {mapped} of {len(children)} school records; aborting.")


def downgrade():
    op.drop_index('uq_enrolments_one_current', table_name='enrolments')
    op.drop_index('ix_enrolments_class_id', table_name='enrolments')
    op.drop_index('ix_enrolments_child_record_id', table_name='enrolments')
    op.drop_table('enrolments')
    op.drop_index('ix_class_teacher_assignments_user_id', table_name='class_teacher_assignments')
    op.drop_index('ix_class_teacher_assignments_class_id', table_name='class_teacher_assignments')
    op.drop_table('class_teacher_assignments')
    op.drop_table('school_classes')
