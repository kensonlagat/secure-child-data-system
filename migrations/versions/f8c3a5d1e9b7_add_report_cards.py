"""add term report cards (#70)

Revision ID: f8c3a5d1e9b7
Revises: e7b2c9f4a6d3
Create Date: 2026-11-18 15:00:00.000000

report_cards and report_card_entries. On PostgreSQL:
- non-owner roles lose UPDATE, DELETE and TRUNCATE, then get UPDATE back on the editable
  columns only (COLUMN_UPDATE_TABLES in app/db_roles.py keeps this on setup-db-roles);
- a trigger refuses any UPDATE or DELETE of a published card, and any INSERT, UPDATE or
  DELETE of an entry whose card is published, for every role including the owner.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f8c3a5d1e9b7'
down_revision = 'e7b2c9f4a6d3'
branch_labels = None
depends_on = None

LEARNING_AREAS = ("english", "kiswahili", "mathematics", "science_technology", "social_studies",
                  "agriculture_nutrition", "creative_arts", "religious_education", "physical_health")

RESTRICT = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name IN ('report_cards', 'report_card_entries')
          AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.report_cards FROM %I', grantee_name);
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.report_card_entries FROM %I', grantee_name);
        EXECUTE format('GRANT UPDATE (status, teacher_comment, updated_by, updated_at, published_by, published_at) '
                       'ON public.report_cards TO %I', grantee_name);
        EXECUTE format('GRANT UPDATE (level, comment, updated_by, updated_at) '
                       'ON public.report_card_entries TO %I', grantee_name);
    END LOOP;
END $$;
"""

LOCK_FUNCTION = """
CREATE OR REPLACE FUNCTION report_card_published_lock() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE card_id integer;
BEGIN
    IF TG_TABLE_NAME = 'report_cards' THEN
        IF OLD.status = 'published' THEN
            RAISE EXCEPTION 'report card % is published and read-only', OLD.id USING ERRCODE = 'check_violation';
        END IF;
    ELSE
        IF TG_OP = 'DELETE' THEN card_id := OLD.report_card_id; ELSE card_id := NEW.report_card_id; END IF;
        IF EXISTS (SELECT 1 FROM public.report_cards WHERE id = card_id AND status = 'published')
           OR (TG_OP = 'UPDATE' AND EXISTS (SELECT 1 FROM public.report_cards
                                           WHERE id = OLD.report_card_id AND status = 'published')) THEN
            RAISE EXCEPTION 'report card % is published and read-only', card_id USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
"""

TRIGGERS = """
CREATE TRIGGER report_cards_published_lock BEFORE UPDATE OR DELETE ON public.report_cards
    FOR EACH ROW EXECUTE FUNCTION report_card_published_lock();
CREATE TRIGGER report_card_entries_published_lock BEFORE INSERT OR UPDATE OR DELETE ON public.report_card_entries
    FOR EACH ROW EXECUTE FUNCTION report_card_published_lock();
"""


def upgrade():
    op.create_table(
        'report_cards',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=False),
        sa.Column('class_id', sa.Integer(), sa.ForeignKey('school_classes.id'), nullable=False),
        sa.Column('academic_year', sa.Integer(), nullable=False),
        sa.Column('term', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False, server_default='draft'),
        sa.Column('teacher_comment', sa.LargeBinary(), nullable=True),  # AES-GCM ciphertext
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('published_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('child_record_id', 'academic_year', 'term', name='uq_report_card_term'),
        sa.CheckConstraint("status IN ('draft', 'published')", name='ck_report_card_status'),
        sa.CheckConstraint('term IN (1, 2, 3)', name='ck_report_card_term'),
    )
    op.create_index('ix_report_cards_child_record_id', 'report_cards', ['child_record_id'])
    op.create_index('ix_report_cards_class_id', 'report_cards', ['class_id'])
    op.create_table(
        'report_card_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('report_card_id', sa.Integer(), sa.ForeignKey('report_cards.id'), nullable=False),
        sa.Column('learning_area', sa.String(length=40), nullable=False),
        sa.Column('level', sa.String(length=2), nullable=False),
        sa.Column('comment', sa.LargeBinary(), nullable=True),  # AES-GCM ciphertext
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('report_card_id', 'learning_area', name='uq_report_card_entry_area'),
        sa.CheckConstraint("level IN ('EE', 'ME', 'AE', 'BE')", name='ck_report_card_entry_level'),
        sa.CheckConstraint("learning_area IN (" + ", ".join(f"'{a}'" for a in LEARNING_AREAS) + ")",
                           name='ck_report_card_entry_area'),
    )
    op.create_index('ix_report_card_entries_report_card_id', 'report_card_entries', ['report_card_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(RESTRICT)
        op.execute(LOCK_FUNCTION)
        op.execute(TRIGGERS)


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute("DROP TRIGGER IF EXISTS report_card_entries_published_lock ON public.report_card_entries")
        op.execute("DROP TRIGGER IF EXISTS report_cards_published_lock ON public.report_cards")
        op.execute("DROP FUNCTION IF EXISTS report_card_published_lock()")
    op.drop_index('ix_report_card_entries_report_card_id', table_name='report_card_entries')
    op.drop_table('report_card_entries')
    op.drop_index('ix_report_cards_class_id', table_name='report_cards')
    op.drop_index('ix_report_cards_child_record_id', table_name='report_cards')
    op.drop_table('report_cards')
