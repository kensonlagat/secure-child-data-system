"""row-level security on child data and the audit log (#19)

Revision ID: c5f1e8a3b7d2
Revises: a9d4b6e2c1f8
Create Date: 2026-11-18 21:00:00.000000

PostgreSQL only (SQLite has no row-level security; the test suite's SQLite runs skip this).

- rls_context_key: an owner-only table. It is created EMPTY: this migration never generates or
  stores a key. `flask setup-db-roles` writes the `rls-context` subkey into it.
- app_hmac_sha256(), app_context_valid() (SECURITY DEFINER: the only reader of the key; rejects
  an unsigned, forged or more-than-5-minutes-old context), app_user_id().
- audit_stats() and parent_has_active_link() (SECURITY DEFINER): return counts, a timestamp or
  a boolean, never rows, so internal checks (lockouts, bounded audit writes, parent sign-in)
  keep working while audit SELECT is limited to administrators (D19.2).
- Policies, with ENABLE and FORCE ROW LEVEL SECURITY:
  - child_records: the union of every access_service path (see the policy text);
  - audit_log_entries: INSERT for any valid context, SELECT for administrator and system;
  - guardian_links: administrators and system, plus a parent's own links;
  - every other table with a child_record_id column (except enrolments, which the teacher
    policy reads): rows whose child is visible under the child_records policy.
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c5f1e8a3b7d2'
down_revision = 'a9d4b6e2c1f8'
branch_labels = None
depends_on = None

# Tables with child_record_id that get the generic policy are found at upgrade time. These two
# have their own handling: enrolments is read by the teacher policy (a policy on it that read
# child_records would recurse), guardian_links has its own non-recursive policy.
EXCLUDED_CHILD_TABLES = ("enrolments", "guardian_links")

VALID = "(SELECT public.app_context_valid())"
ROLE = "current_setting('app.role', true)"

CHILD_SCOPE = f"""{VALID} AND (
    {ROLE} IN ('administrator', 'system')
    OR (NOT is_deleted AND NOT is_archived AND (
        ({ROLE} IN ('school_nurse', 'principal') AND institution_mode = 'school')
        OR ({ROLE} IN ('social_worker', 'legal_officer', 'home_manager') AND institution_mode = 'childrens_home')
        OR ({ROLE} = 'teacher' AND institution_mode = 'school' AND id IN (
            SELECT e.child_record_id FROM public.enrolments e
            JOIN public.class_teacher_assignments a ON a.class_id = e.class_id
            JOIN public.school_classes c ON c.id = a.class_id
            WHERE e.ended_on IS NULL AND a.ended_at IS NULL AND c.is_active
              AND a.user_id = public.app_user_id()))
        OR ({ROLE} = 'parent_guardian' AND institution_mode = 'school' AND id IN (
            SELECT gl.child_record_id FROM public.guardian_links gl
            WHERE gl.status = 'active' AND gl.guardian_user_id = public.app_user_id()))
    )))"""

FUNCTIONS = r"""
CREATE TABLE public.rls_context_key (
    id integer PRIMARY KEY CHECK (id = 1),
    key bytea NOT NULL
);
REVOKE ALL ON public.rls_context_key FROM PUBLIC;
DO $$
DECLARE grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT grantee FROM information_schema.role_table_grants
        WHERE table_schema = 'public' AND table_name = 'rls_context_key'
          AND grantee <> current_user AND grantee <> 'PUBLIC'
    LOOP
        EXECUTE format('REVOKE ALL ON public.rls_context_key FROM %I', grantee_name);
    END LOOP;
END $$;

CREATE FUNCTION public.app_hmac_sha256(key bytea, message bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
DECLARE k bytea := key; inner_pad bytea; outer_pad bytea; i integer;
BEGIN
    IF length(k) > 64 THEN k := sha256(k); END IF;
    k := k || decode(repeat('00', 64 - length(k)), 'hex');
    inner_pad := k; outer_pad := k;
    FOR i IN 0..63 LOOP
        inner_pad := set_byte(inner_pad, i, get_byte(k, i) # 54);
        outer_pad := set_byte(outer_pad, i, get_byte(k, i) # 92);
    END LOOP;
    RETURN sha256(outer_pad || sha256(inner_pad || message));
END $$;

CREATE FUNCTION public.app_context_valid() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    k bytea;
    u text := current_setting('app.user_id', true);
    r text := current_setting('app.role', true);
    m text := current_setting('app.mode', true);
    i text := current_setting('app.issued_at', true);
    s text := current_setting('app.context_sig', true);
    issued timestamptz;
BEGIN
    IF r IS NULL OR r = '' OR s IS NULL OR i IS NULL OR i !~ '^[0-9]{1,12}$' THEN
        RETURN false;
    END IF;
    issued := to_timestamp(i::bigint);
    IF issued < now() - interval '5 minutes' OR issued > now() + interval '1 minute' THEN
        RETURN false;
    END IF;
    SELECT rk.key INTO k FROM public.rls_context_key rk WHERE rk.id = 1;
    IF k IS NULL THEN
        RETURN false;
    END IF;
    RETURN s = encode(public.app_hmac_sha256(
        k, convert_to(coalesce(u, '') || '|' || r || '|' || coalesce(m, '') || '|' || i, 'UTF8')), 'hex');
END $$;

CREATE FUNCTION public.app_user_id() RETURNS integer
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT CASE WHEN current_setting('app.user_id', true) ~ '^[0-9]{1,9}$'
                THEN current_setting('app.user_id', true)::integer END
$$;

CREATE FUNCTION public.audit_stats(
    p_action text, p_since timestamp, p_user_id integer, p_user_null boolean, p_identifier text,
    p_ip text, p_details text, p_target_type text, p_target_id integer, p_target_null boolean)
RETURNS TABLE (row_count bigint, latest timestamp)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT count(*), max(e.timestamp) FROM public.audit_log_entries e
    WHERE (SELECT public.app_context_valid())
      AND e.action = p_action
      AND (p_since IS NULL OR e.timestamp > p_since)
      AND (p_user_id IS NULL OR e.user_id = p_user_id)
      AND (NOT p_user_null OR e.user_id IS NULL)
      AND (p_identifier IS NULL OR e.attempted_identifier = p_identifier)
      AND (p_ip IS NULL OR e.ip_address = p_ip)
      AND (p_details IS NULL OR e.details = p_details)
      AND (p_target_type IS NULL OR e.target_record_type = p_target_type)
      AND (p_target_id IS NULL OR e.target_record_id = p_target_id)
      AND (NOT p_target_null OR e.target_record_id IS NULL)
$$;

CREATE FUNCTION public.parent_has_active_link(p_user_id integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT (SELECT public.app_context_valid()) AND EXISTS (
        SELECT 1 FROM public.guardian_links gl JOIN public.child_records c ON c.id = gl.child_record_id
        WHERE gl.guardian_user_id = p_user_id AND gl.status = 'active' AND c.institution_mode = 'school'
          AND NOT c.is_deleted AND NOT c.is_archived)
$$;

REVOKE ALL ON FUNCTION public.app_context_valid() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_stats(text, timestamp, integer, boolean, text, text, text, text, integer, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.parent_has_active_link(integer) FROM PUBLIC;
"""

POLICIES = f"""
ALTER TABLE public.child_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.child_records FORCE ROW LEVEL SECURITY;
CREATE POLICY child_records_select ON public.child_records FOR SELECT USING ({CHILD_SCOPE});
CREATE POLICY child_records_update ON public.child_records FOR UPDATE USING ({CHILD_SCOPE}) WITH CHECK ({CHILD_SCOPE});
CREATE POLICY child_records_insert ON public.child_records FOR INSERT
    WITH CHECK ({VALID} AND {ROLE} IN ('administrator', 'system'));

ALTER TABLE public.audit_log_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_insert ON public.audit_log_entries FOR INSERT WITH CHECK ({VALID});
CREATE POLICY audit_select ON public.audit_log_entries FOR SELECT
    USING ({VALID} AND {ROLE} IN ('administrator', 'system'));

ALTER TABLE public.guardian_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guardian_links FORCE ROW LEVEL SECURITY;
CREATE POLICY guardian_links_select ON public.guardian_links FOR SELECT USING ({VALID} AND (
    {ROLE} IN ('administrator', 'system')
    OR ({ROLE} = 'parent_guardian' AND guardian_user_id = public.app_user_id())));
CREATE POLICY guardian_links_write ON public.guardian_links FOR UPDATE
    USING ({VALID} AND {ROLE} IN ('administrator', 'system'))
    WITH CHECK ({VALID} AND {ROLE} IN ('administrator', 'system'));
CREATE POLICY guardian_links_insert ON public.guardian_links FOR INSERT
    WITH CHECK ({VALID} AND {ROLE} IN ('administrator', 'system'));

DO $$
DECLARE t text;
BEGIN
    FOR t IN
        SELECT c.table_name FROM information_schema.columns c
        JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
        WHERE c.table_schema = 'public' AND c.column_name = 'child_record_id' AND tb.table_type = 'BASE TABLE'
          AND c.table_name NOT IN ({", ".join(f"'{t}'" for t in EXCLUDED_CHILD_TABLES)})
    LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY child_scope_select ON public.%I FOR SELECT USING '
                       '((SELECT public.app_context_valid()) AND child_record_id IN (SELECT id FROM public.child_records))', t);
        EXECUTE format('CREATE POLICY child_scope_update ON public.%I FOR UPDATE USING '
                       '((SELECT public.app_context_valid()) AND child_record_id IN (SELECT id FROM public.child_records)) '
                       'WITH CHECK ((SELECT public.app_context_valid()) AND child_record_id IN (SELECT id FROM public.child_records))', t);
        EXECUTE format('CREATE POLICY child_scope_insert ON public.%I FOR INSERT WITH CHECK '
                       '((SELECT public.app_context_valid()) AND child_record_id IN (SELECT id FROM public.child_records))', t);
    END LOOP;
END $$;
"""

DROP_POLICIES = """
DO $$
DECLARE p record;
BEGIN
    FOR p IN
        SELECT schemaname, tablename, policyname FROM pg_policies
        WHERE schemaname = 'public' AND (policyname LIKE 'child_scope_%' OR policyname LIKE 'child_records_%'
              OR policyname LIKE 'audit_%' OR policyname LIKE 'guardian_links_%')
    LOOP
        EXECUTE format('DROP POLICY %I ON %I.%I', p.policyname, p.schemaname, p.tablename);
        EXECUTE format('ALTER TABLE %I.%I NO FORCE ROW LEVEL SECURITY', p.schemaname, p.tablename);
        EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY', p.schemaname, p.tablename);
    END LOOP;
END $$;
DROP FUNCTION IF EXISTS public.parent_has_active_link(integer);
DROP FUNCTION IF EXISTS public.audit_stats(text, timestamp, integer, boolean, text, text, text, text, integer, boolean);
DROP FUNCTION IF EXISTS public.app_user_id();
DROP FUNCTION IF EXISTS public.app_context_valid();
DROP FUNCTION IF EXISTS public.app_hmac_sha256(bytea, bytea);
DROP TABLE IF EXISTS public.rls_context_key;
"""


def upgrade():
    if op.get_bind().dialect.name != 'postgresql':
        return
    op.execute(FUNCTIONS)
    op.execute(POLICIES)


def downgrade():
    if op.get_bind().dialect.name != 'postgresql':
        return
    op.execute(DROP_POLICIES)
