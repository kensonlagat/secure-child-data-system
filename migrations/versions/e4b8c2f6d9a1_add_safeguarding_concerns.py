"""safeguarding concerns (#62)

Revision ID: e4b8c2f6d9a1
Revises: c5f1e8a3b7d2
Create Date: 2026-11-18 13:00:00.000000

Two tables: safeguarding_concerns and safeguarding_concern_actions (narrative and action notes
are AES-GCM ciphertext). On PostgreSQL, as the owner:
- grants: non-owner roles lose UPDATE, DELETE and TRUNCATE on both tables, then get UPDATE back on
  the concern's status columns only (COLUMN_UPDATE_TABLES and APPEND_ONLY_TABLES in
  app/db_roles.py keep this on setup-db-roles). The narrative can't be changed after submission
  and nothing is ever deleted;
- a trigger refuses changing child_record_id once it is set (it may be set once, while NULL);
- helper functions: app_is_safeguarding_lead(mode) (is the context's user an active, non-admin
  safeguarding lead whose role is in that mode), safeguarding_child_name(concern) and
  safeguarding_link_target_ok(child, mode) (SECURITY DEFINER, for leads only: a lead may not be
  able to see the child row under its own role's scope);
- row-level security, ENABLE and FORCE, with policies written out here as fixed text (the #137
  lesson: an old migration must not change when app code changes):
  - concerns: administrators and system see every row (metadata only in the app); the reporter
    sees their own; a lead sees concerns in their mode. Insert: the signed-in user as reporter,
    no parents, and the child (if any) must be visible to them. Update: system, or a lead in the
    mode who did not report it;
  - actions (no child_record_id; listed in CHILD_DATA_VIA_PARENT, scoped through the concern):
    only system, or a lead in the mode who did not report the concern. Administrators and
    reporters get no action rows at all.
  Any generic child_scope_/parent_scope_ policy that the #19 migration's loops might have created
  on these tables is dropped first, so only these policies apply.
"""
import sqlalchemy as sa
import sqlalchemy_utils  # noqa: F401  (house rule for migrations touching encrypted columns)
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e4b8c2f6d9a1'
down_revision = 'c5f1e8a3b7d2'
branch_labels = None
depends_on = None

# Fixed copy of this migration's CHILD_DATA_VIA_PARENT entry (app/db_roles.py has the live list).
CHILD_DATA_VIA_PARENT = {"safeguarding_concern_actions": ("concern_id", "safeguarding_concerns")}

VALID = "(SELECT public.app_context_valid())"
ROLE = "current_setting('app.role', true)"
USER = "public.app_user_id()"

RESTRICT = """
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name IN ('safeguarding_concerns', 'safeguarding_concern_actions')
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.safeguarding_concerns FROM %I', grantee_name);
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.safeguarding_concern_actions FROM %I', grantee_name);
        EXECUTE format('GRANT UPDATE (status, urgency, child_record_id, updated_at, closed_at, closed_by) '
                       'ON public.safeguarding_concerns TO %I', grantee_name);
    END LOOP;
END $$;
"""

FUNCTIONS = """
CREATE FUNCTION public.safeguarding_child_set_once() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF OLD.child_record_id IS NOT NULL AND NEW.child_record_id IS DISTINCT FROM OLD.child_record_id THEN
        RAISE EXCEPTION 'the child of concern % is already set', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER safeguarding_child_set_once BEFORE UPDATE ON public.safeguarding_concerns
    FOR EACH ROW EXECUTE FUNCTION public.safeguarding_child_set_once();

CREATE FUNCTION public.app_is_safeguarding_lead(p_mode text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT (SELECT public.app_context_valid()) AND EXISTS (
        SELECT 1 FROM public.users u JOIN public.roles r ON r.id = u.role_id
        WHERE u.id = public.app_user_id() AND u.is_active AND u.is_safeguarding_lead
          AND r.name NOT IN ('administrator', 'parent_guardian') AND r.institution_mode = p_mode)
$$;

CREATE FUNCTION public.safeguarding_child_name(p_concern integer) RETURNS bytea
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT c.full_name FROM public.safeguarding_concerns s JOIN public.child_records c ON c.id = s.child_record_id
    WHERE s.id = p_concern AND public.app_is_safeguarding_lead(s.institution_mode)
      AND s.reporter_id IS DISTINCT FROM public.app_user_id()
$$;

CREATE FUNCTION public.safeguarding_link_target_ok(p_child integer, p_mode text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT public.app_is_safeguarding_lead(p_mode) AND EXISTS (
        SELECT 1 FROM public.child_records c
        WHERE c.id = p_child AND c.institution_mode = p_mode AND NOT c.is_deleted AND NOT c.is_archived)
$$;

REVOKE ALL ON FUNCTION public.app_is_safeguarding_lead(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.safeguarding_child_name(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.safeguarding_link_target_ok(integer, text) FROM PUBLIC;
-- The roles that can read child_records (the app role) may call them straight away, so there is
-- no window where the policies below fail; setup-db-roles grants the same.
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'child_records' AND privilege_type = 'SELECT'
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.app_is_safeguarding_lead(text) TO %I', grantee_name);
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.safeguarding_child_name(integer) TO %I', grantee_name);
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.safeguarding_link_target_ok(integer, text) TO %I',
                       grantee_name);
    END LOOP;
END $$;
"""

LEAD_OF = "public.app_is_safeguarding_lead({mode})"

POLICIES = f"""
DO $$
DECLARE p record;
BEGIN
    FOR p IN SELECT policyname, tablename FROM pg_policies
             WHERE schemaname = 'public' AND tablename IN ('safeguarding_concerns', 'safeguarding_concern_actions')
    LOOP
        EXECUTE format('DROP POLICY %I ON public.%I', p.policyname, p.tablename);
    END LOOP;
END $$;

ALTER TABLE public.safeguarding_concerns ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.safeguarding_concerns FORCE ROW LEVEL SECURITY;
CREATE POLICY concern_select ON public.safeguarding_concerns FOR SELECT USING ({VALID} AND (
    {ROLE} IN ('administrator', 'system')
    OR reporter_id = {USER}
    OR {LEAD_OF.format(mode="institution_mode")}));
CREATE POLICY concern_insert ON public.safeguarding_concerns FOR INSERT WITH CHECK ({VALID} AND (
    {ROLE} = 'system'
    OR ({ROLE} NOT IN ('anonymous', 'parent_guardian') AND reporter_id = {USER}
        AND (child_record_id IS NULL OR child_record_id IN (SELECT id FROM public.child_records)))));
CREATE POLICY concern_update ON public.safeguarding_concerns FOR UPDATE
    USING ({VALID} AND ({ROLE} = 'system'
           OR ({LEAD_OF.format(mode="institution_mode")} AND reporter_id IS DISTINCT FROM {USER})))
    WITH CHECK ({VALID} AND ({ROLE} = 'system'
           OR ({LEAD_OF.format(mode="institution_mode")} AND reporter_id IS DISTINCT FROM {USER})));

ALTER TABLE public.safeguarding_concern_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.safeguarding_concern_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY concern_action_select ON public.safeguarding_concern_actions FOR SELECT USING ({VALID} AND (
    {ROLE} = 'system'
    OR concern_id IN (SELECT s.id FROM public.safeguarding_concerns s
                      WHERE {LEAD_OF.format(mode="s.institution_mode")} AND s.reporter_id IS DISTINCT FROM {USER})));
CREATE POLICY concern_action_insert ON public.safeguarding_concern_actions FOR INSERT WITH CHECK ({VALID} AND (
    {ROLE} = 'system'
    OR (actor_id = {USER}
        AND concern_id IN (SELECT s.id FROM public.safeguarding_concerns s
                           WHERE {LEAD_OF.format(mode="s.institution_mode")}
                             AND s.reporter_id IS DISTINCT FROM {USER}))));
"""


def upgrade():
    op.create_table(
        'safeguarding_concerns',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('child_record_id', sa.Integer(), sa.ForeignKey('child_records.id'), nullable=True),
        sa.Column('institution_mode', sa.String(length=20), nullable=False),
        sa.Column('reporter_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('involves_staff', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('urgency', sa.String(length=10), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False, server_default='open'),
        sa.Column('narrative', sa.LargeBinary(), nullable=False),  # AES-GCM ciphertext
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('closed_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.CheckConstraint("urgency IN ('low', 'medium', 'high', 'immediate')", name='ck_concern_urgency'),
        sa.CheckConstraint("status IN ('open', 'triaged', 'referred', 'closed')", name='ck_concern_status'),
        sa.CheckConstraint("institution_mode IN ('school', 'childrens_home')", name='ck_concern_mode'),
    )
    op.create_index('ix_safeguarding_concerns_child_record_id', 'safeguarding_concerns', ['child_record_id'])
    op.create_index('ix_safeguarding_concerns_reporter_id', 'safeguarding_concerns', ['reporter_id'])
    op.create_table(
        'safeguarding_concern_actions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('concern_id', sa.Integer(), sa.ForeignKey('safeguarding_concerns.id'), nullable=False),
        sa.Column('actor_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('action_type', sa.String(length=20), nullable=False),
        sa.Column('body', sa.LargeBinary(), nullable=True),  # AES-GCM ciphertext
        sa.Column('referral_agency', sa.String(length=30), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("action_type IN ('note', 'status_change', 'referral', 'closure')",
                           name='ck_concern_action_type'),
        sa.CheckConstraint("referral_agency IS NULL OR referral_agency IN ('childrens_officer', 'police', "
                           "'health', 'other')", name='ck_concern_action_agency'),
    )
    op.create_index('ix_safeguarding_concern_actions_concern_id', 'safeguarding_concern_actions', ['concern_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute(RESTRICT)
        op.execute(FUNCTIONS)
        op.execute(POLICIES)


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute("DROP TRIGGER IF EXISTS safeguarding_child_set_once ON public.safeguarding_concerns")
    op.drop_index('ix_safeguarding_concern_actions_concern_id', table_name='safeguarding_concern_actions')
    op.drop_table('safeguarding_concern_actions')
    op.drop_index('ix_safeguarding_concerns_reporter_id', table_name='safeguarding_concerns')
    op.drop_index('ix_safeguarding_concerns_child_record_id', table_name='safeguarding_concerns')
    op.drop_table('safeguarding_concerns')
    if op.get_bind().dialect.name == 'postgresql':
        op.execute("DROP FUNCTION IF EXISTS public.safeguarding_link_target_ok(integer, text)")
        op.execute("DROP FUNCTION IF EXISTS public.safeguarding_child_name(integer)")
        op.execute("DROP FUNCTION IF EXISTS public.app_is_safeguarding_lead(text)")
        op.execute("DROP FUNCTION IF EXISTS public.safeguarding_child_set_once()")
