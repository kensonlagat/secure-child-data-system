"""Least-privilege PostgreSQL roles for the web app (#72).

Two roles:
- the **owner** role owns every table and the purge function, and runs migrations
  (through MIGRATION_DATABASE_URL);
- the **app** role is what DATABASE_URL uses. It may read, insert and update app tables,
  may only read and insert audit rows, may delete nothing, and may purge synthetic audit
  rows only through purge_synthetic_audit_entries().

`flask setup-db-roles` creates or updates both roles (run once as a superuser, and again
after migrations that add tables or functions). `flask check-db-privileges` connects with
the app's own DATABASE_URL and proves the restrictions hold. Passwords come from
environment variables or a hidden prompt, are passed to PostgreSQL as quoted literals,
and are never printed or written to any file.
"""

import re

import psycopg2
from psycopg2 import errors, sql

ROLE_NAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
AUDIT_TABLE = "audit_log_entries"
# Append-only tables: the app role may read and insert, never update (and nothing is ever
# deletable). Every future append-only table must be added here when it is created.
APPEND_ONLY_TABLES = (AUDIT_TABLE, "consent_records", "attendance_corrections", "absence_alerts",
                      "clinic_visits", "case_notes", "health_entries", "medication_administrations",
                      "family_visits", "placements", "document_blobs",
                      "child_photos", "safeguarding_concern_actions")
# Tables the app role may update only in these columns (everything else is fixed once written).
COLUMN_UPDATE_TABLES = {
    "authorised_collectors": ("status", "decided_by", "decided_at", "is_active", "revoked_by", "revoked_at"),
    "documents": ("is_deleted", "deleted_at"),
    # Report cards (#70): only the editable fields; ids, child, class, term and creator are fixed.
    # A trigger also refuses any change once a card is published.
    "report_cards": ("status", "teacher_comment", "updated_by", "updated_at", "published_by", "published_at"),
    "report_card_entries": ("level", "comment", "updated_by", "updated_at"),
    # Guardian links (#67): only the status columns; who is linked to whom never changes.
    "guardian_links": ("status", "verified_by", "verified_at", "revoked_by", "revoked_at"),
    # Safeguarding concerns (#62): status columns only, so the narrative can't change after
    # submission. child_record_id is set once, while NULL (a trigger refuses re-linking).
    "safeguarding_concerns": ("status", "urgency", "child_record_id", "updated_at", "closed_at", "closed_by"),
}
MIGRATION_TABLE = "alembic_version"
# Row-level security (#19): the context key lives in an owner-only table the app role can't read.
RLS_KEY_TABLE = "rls_context_key"
OWNER_ONLY_TABLES = (MIGRATION_TABLE, RLS_KEY_TABLE)
# SECURITY DEFINER helpers the app role may call. They return booleans or counts, never rows.
RLS_APP_FUNCTIONS = ("app_context_valid()",
                     "audit_stats(text, timestamp, integer, boolean, text, text, text, text, integer, boolean)",
                     "parent_has_active_link(integer)",
                     # #62: for safeguarding leads; booleans or the child's encrypted name only.
                     "app_is_safeguarding_lead(text)", "safeguarding_child_name(integer)",
                     "safeguarding_link_target_ok(integer, text)")
RLS_TABLES = ("child_records", "audit_log_entries", "guardian_links")
# Child data in tables WITHOUT a child_record_id column, scoped through their parent row:
# table -> (foreign key column, parent table). The parent's own policy then applies. The one
# list used by both the row-level security migration and check-db-privileges. Add a table here
# only together with a migration that creates its policies (the #19 migration skips entries
# whose table doesn't exist yet).
CHILD_DATA_VIA_PARENT = {
    "report_card_entries": ("report_card_id", "report_cards"),
    "document_blobs": ("document_id", "documents"),
    "medication_administrations": ("schedule_id", "medication_schedules"),
    "aftercare_followups": ("placement_id", "placements"),
    "attendance_corrections": ("mark_id", "attendance_marks"),
    # #62: its own, stricter policies (leads only) are written as fixed text in its migration.
    "safeguarding_concern_actions": ("concern_id", "safeguarding_concerns"),
}
# Tables that reference forced tables but deliberately have no policy of their own:
# enrolments is read by the teacher branch of the child_records policy (a policy on it that read
# child_records would recurse); anomaly_alerts references audit rows and is administrator-only.
RLS_REFERENCING_EXEMPT = ("enrolments", "anomaly_alerts")
PURGE_FUNCTION = "purge_synthetic_audit_entries()"


def validate_role_name(name):
    """Reject anything that is not a plain lower-case PostgreSQL identifier."""
    if not ROLE_NAME_PATTERN.fullmatch(name or ""):
        raise ValueError(f"Invalid role name: {name!r}")
    return name


def _role_exists(cursor, name):
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,))
    return cursor.fetchone() is not None


def _ensure_login_role(cursor, name, password, bypass_rls=False):
    """Create the role (or update its password) with no special privileges.

    Only the owner role gets BYPASSRLS (#19): it runs migrations and pg_dump, and owns the
    SECURITY DEFINER helpers that count audit rows. The app role never gets it."""
    attributes = sql.SQL("LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION {}").format(
        sql.SQL("BYPASSRLS" if bypass_rls else "NOBYPASSRLS"))
    if not _role_exists(cursor, name):
        if not password:
            raise ValueError(f"A password is required to create role {name}.")
        cursor.execute(
            sql.SQL("CREATE ROLE {} {} PASSWORD {}").format(
                sql.Identifier(name), attributes, sql.Literal(password)
            )
        )
        return "created"
    cursor.execute(sql.SQL("ALTER ROLE {} {}").format(sql.Identifier(name), attributes))
    if password:
        cursor.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(name), sql.Literal(password))
        )
        return "updated (password changed)"
    return "updated"


def setup_roles(dsn, owner_role, app_role, owner_password=None, app_password=None, rls_key=None):
    """Create or update both roles and apply ownership and grants. Returns a list of steps."""
    owner_role = validate_role_name(owner_role)
    app_role = validate_role_name(app_role)
    if owner_role == app_role:
        raise ValueError("The owner and app roles must be different.")

    owner, app = sql.Identifier(owner_role), sql.Identifier(app_role)
    steps = []
    connection = psycopg2.connect(dsn)
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                if not cursor.fetchone()[0]:
                    raise PermissionError("setup-db-roles must run as a PostgreSQL superuser.")
                cursor.execute("SELECT current_database()")
                database = sql.Identifier(cursor.fetchone()[0])

                steps.append(f"owner role {owner_role}: "
                             f"{_ensure_login_role(cursor, owner_role, owner_password, bypass_rls=True)}")
                steps.append(f"app role {app_role}: {_ensure_login_role(cursor, app_role, app_password)}")

                # Database and schema: nobody else may connect or create objects.
                cursor.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(database))
                cursor.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(database, owner, app))
                cursor.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
                cursor.execute(sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(owner))
                cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(app))

                # The owner role owns every table (sequences follow their tables).
                cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                tables = [row[0] for row in cursor.fetchall()]
                for table in tables:
                    cursor.execute(
                        sql.SQL("ALTER TABLE public.{} OWNER TO {}").format(sql.Identifier(table), owner)
                    )
                steps.append(f"ownership of {len(tables)} tables -> {owner_role}")

                # App role: read, insert and update app tables; delete nothing.
                cursor.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(app))
                for table in tables:
                    if table in OWNER_ONLY_TABLES:
                        continue  # the app never touches migration state or the RLS key
                    privileges = (
                        sql.SQL("SELECT, INSERT")
                        if table in APPEND_ONLY_TABLES or table in COLUMN_UPDATE_TABLES
                        else sql.SQL("SELECT, INSERT, UPDATE")
                    )
                    cursor.execute(
                        sql.SQL("GRANT {} ON public.{} TO {}").format(privileges, sql.Identifier(table), app)
                    )
                    if table in COLUMN_UPDATE_TABLES:
                        cursor.execute(
                            sql.SQL("GRANT UPDATE ({}) ON public.{} TO {}").format(
                                sql.SQL(", ").join(sql.Identifier(c) for c in COLUMN_UPDATE_TABLES[table]),
                                sql.Identifier(table), app,
                            )
                        )
                cursor.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(app))
                steps.append(
                    f"{app_role}: SELECT, INSERT, UPDATE on app tables; SELECT, INSERT only on "
                    f"{', '.join(APPEND_ONLY_TABLES)}; nothing on {MIGRATION_TABLE}; no DELETE or TRUNCATE anywhere"
                )

                # Tables and sequences the owner creates later get the same app-table grants.
                cursor.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                        "GRANT SELECT, INSERT, UPDATE ON TABLES TO {}"
                    ).format(owner, app)
                )
                cursor.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                        "GRANT USAGE, SELECT ON SEQUENCES TO {}"
                    ).format(owner, app)
                )

                # Row-level security (#19): store the context key, own and grant the helpers.
                cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{RLS_KEY_TABLE}",))
                if cursor.fetchone()[0]:
                    if rls_key is None:
                        raise ValueError("The RLS context key is required once rls_context_key exists.")
                    cursor.execute(
                        sql.SQL("INSERT INTO public.{} (id, key) VALUES (1, %s) "
                                "ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key").format(sql.Identifier(RLS_KEY_TABLE)),
                        (psycopg2.Binary(rls_key),))
                    for function in RLS_APP_FUNCTIONS:
                        cursor.execute("SELECT to_regprocedure(%s) IS NOT NULL", (f"public.{function}",))
                        if not cursor.fetchone()[0]:
                            continue  # its migration hasn't run on this database yet
                        cursor.execute(sql.SQL(f"ALTER FUNCTION public.{function} OWNER TO {{}}").format(owner))
                        cursor.execute(sql.SQL(f"REVOKE ALL ON FUNCTION public.{function} FROM PUBLIC"))
                        cursor.execute(sql.SQL(f"GRANT EXECUTE ON FUNCTION public.{function} TO {{}}").format(app))
                    steps.append(f"row-level security: context key stored in {RLS_KEY_TABLE} (owner only); "
                                 f"{owner_role} has BYPASSRLS, {app_role} does not")

                # Restricted purge path for synthetic audit rows.
                cursor.execute("SELECT to_regprocedure(%s) IS NOT NULL", (f"public.{PURGE_FUNCTION}",))
                if cursor.fetchone()[0]:
                    cursor.execute(sql.SQL(f"ALTER FUNCTION public.{PURGE_FUNCTION} OWNER TO {{}}").format(owner))
                    cursor.execute(sql.SQL(f"REVOKE ALL ON FUNCTION public.{PURGE_FUNCTION} FROM PUBLIC"))
                    cursor.execute(sql.SQL(f"GRANT EXECUTE ON FUNCTION public.{PURGE_FUNCTION} TO {{}}").format(app))
                    steps.append(f"{PURGE_FUNCTION}: owned by {owner_role}, EXECUTE granted to {app_role} only")
                else:
                    steps.append(f"{PURGE_FUNCTION} not found yet: run migrations, then rerun this command")
    finally:
        connection.close()
    return steps


def check_privileges(dsn, sign_context=None):
    """Connect as the configured app role and prove the restrictions. Returns (ok, lines).

    sign_context: a function taking a backend process id and returning the settings of a valid
    signed `system` context for that connection (app/rls.py). Used to prove that inserts work
    with a context and are refused without one (#19)."""
    lines, ok = [], True
    connection = psycopg2.connect(dsn)
    signed_context = None
    try:
        if sign_context is not None:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                signed_context = sign_context(cursor.fetchone()[0])
            connection.rollback()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
            user, is_super, create_role, create_db, bypass_rls = cursor.fetchone()
            lines.append(f"connected as: {user}")
            if is_super or create_role or create_db or bypass_rls:
                ok = False
                lines.append("FAIL: the app role has superuser, createrole, createdb or bypassrls")
            else:
                lines.append("PASS: no superuser, createrole, createdb or bypassrls")
            connection.rollback()

        def record(label, worked, should_work, note=""):
            nonlocal ok
            passed = worked is not None and worked == should_work
            ok = ok and passed
            if worked is None:
                outcome = f"could not be tested ({note})"
            else:
                outcome = "allowed" if worked else "refused"
            lines.append(f"{'PASS' if passed else 'FAIL'}: {label} is {outcome}")

        def attempt(label, statement, should_work):
            # Probes are no-ops (WHERE false) or rolled back; nothing is ever kept.
            with connection.cursor() as cursor:
                note = ""
                try:
                    cursor.execute(statement)
                    worked = True
                except errors.InsufficientPrivilege:
                    worked = False
                except psycopg2.Error as error:  # any other error is reported, never a crash
                    worked, note = None, type(error).__name__
                finally:
                    connection.rollback()
            record(label, worked, should_work, note)

        def has_privilege(label, table, privilege, should_have):
            with connection.cursor() as cursor:
                cursor.execute("SELECT has_table_privilege(current_user, %s, %s)", (table, privilege))
                worked = cursor.fetchone()[0]
                connection.rollback()
            record(label, worked, should_have)

        with connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.rls_context_key') IS NOT NULL")
            rls_installed = cursor.fetchone()[0]
            connection.rollback()

        def with_context(statement):
            settings = "".join(
                f"SELECT set_config({sql.Literal(name).as_string(connection)}, "
                f"{sql.Literal(value).as_string(connection)}, true); "
                for name, value in (signed_context or {}).items())
            return settings + statement

        attempt("SELECT on audit_log_entries", "SELECT count(*) FROM audit_log_entries", True)
        insert_audit = ("INSERT INTO audit_log_entries (action, attempted_identifier, is_synthetic) "
                        "VALUES ('privilege_check', 'privilege-check', true)")
        if rls_installed:
            attempt("INSERT into audit_log_entries without a signed context (row-level security)",
                    insert_audit, False)
            if signed_context:
                attempt("INSERT into audit_log_entries with a signed context", with_context(insert_audit), True)
        else:
            attempt("INSERT into audit_log_entries", insert_audit, True)
        attempt("UPDATE on audit_log_entries", "UPDATE audit_log_entries SET details = details WHERE false", False)
        attempt("DELETE on audit_log_entries", "DELETE FROM audit_log_entries WHERE false", False)
        has_privilege("TRUNCATE on audit_log_entries", AUDIT_TABLE, "TRUNCATE", False)
        attempt("DELETE on child_records", "DELETE FROM child_records WHERE false", False)
        attempt("UPDATE on child_records", "UPDATE child_records SET id = id WHERE false", True)
        attempt("UPDATE on alembic_version", "UPDATE alembic_version SET version_num = version_num WHERE false", False)
        attempt("CREATE TABLE", "CREATE TABLE privilege_check_probe (id integer)", False)
        attempt("purge_synthetic_audit_entries()", "SELECT purge_synthetic_audit_entries()", True)
        for table in APPEND_ONLY_TABLES:
            if table == AUDIT_TABLE:
                continue  # checked in detail above
            with connection.cursor() as cursor:
                cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{table}",))
                exists = cursor.fetchone()[0]
                connection.rollback()
            if exists:
                has_privilege(f"UPDATE on {table} (append-only)", table, "UPDATE", False)
                has_privilege(f"DELETE on {table} (append-only)", table, "DELETE", False)
        for table, columns in COLUMN_UPDATE_TABLES.items():
            with connection.cursor() as cursor:
                cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{table}",))
                exists = cursor.fetchone()[0]
                if exists:
                    cursor.execute(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = %s", (table,))
                    all_columns = [row[0] for row in cursor.fetchall()]
                connection.rollback()
            if not exists:
                continue
            has_privilege(f"table-wide UPDATE on {table}", table, "UPDATE", False)
            has_privilege(f"DELETE on {table}", table, "DELETE", False)
            for column in all_columns:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT has_column_privilege(current_user, %s, %s, 'UPDATE')", (table, column))
                    allowed = cursor.fetchone()[0]
                    connection.rollback()
                record(f"UPDATE on {table}.{column}", allowed, column in columns)
        if rls_installed:
            _check_rls(connection, record)
    finally:
        connection.close()
    return ok, lines


def _check_rls(connection, record):
    """Row-level security (#19): forced on every child data table and the audit log, nothing
    visible without a valid context, the key unreadable, and no bypass for the app role."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT DISTINCT c.table_name FROM information_schema.columns c "
            "JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
            "WHERE c.table_schema = 'public' AND c.column_name = 'child_record_id' AND t.table_type = 'BASE TABLE' "
            "AND c.table_name <> 'enrolments'")
        tables = sorted(set(RLS_TABLES) | {row[0] for row in cursor.fetchall()} | set(CHILD_DATA_VIA_PARENT))
        for table in tables:
            cursor.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                           "WHERE oid = to_regclass(%s)", (f"public.{table}",))
            row = cursor.fetchone()
            enabled, forced = row if row and row[0] is not None else (False, False)  # missing = unforced
            record(f"skipping row-level security (ENABLE and FORCE) on {table}", not (enabled and forced), False)
        # Any other table that points at a forced table (child data reached through a parent row)
        # must be forced too, or be listed as deliberately exempt.
        cursor.execute(
            "SELECT DISTINCT src.relname FROM pg_constraint con "
            "JOIN pg_class src ON src.oid = con.conrelid JOIN pg_class ref ON ref.oid = con.confrelid "
            "JOIN pg_namespace n ON n.oid = src.relnamespace "
            "WHERE con.contype = 'f' AND n.nspname = 'public' AND ref.relforcerowsecurity "
            "AND NOT src.relforcerowsecurity ORDER BY 1")
        for (table,) in cursor.fetchall():
            if table not in RLS_REFERENCING_EXEMPT:
                record(f"leaving {table} (references a row-level-secured table) without row-level security",
                       True, False)
        cursor.execute("SELECT has_table_privilege(current_user, 'public.rls_context_key', 'SELECT')")
        record("SELECT on rls_context_key", cursor.fetchone()[0], False)
        cursor.execute("SELECT count(*) FROM child_records")
        record("seeing child_records rows without a signed context", cursor.fetchone()[0] > 0, False)
        cursor.execute("SELECT set_config('app.role', 'administrator', true), set_config('app.user_id', '1', true), "
                       "set_config('app.mode', 'both', true), "
                       "set_config('app.issued_at', extract(epoch from now())::bigint::text, true), "
                       "set_config('app.context_sig', 'forged', true)")
        cursor.execute("SELECT count(*) FROM child_records")
        record("seeing child_records rows with a forged context", cursor.fetchone()[0] > 0, False)
        connection.rollback()
        cursor.execute("SELECT r.rolbypassrls FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                       "WHERE p.proname = 'app_context_valid'")
        row = cursor.fetchone()
        record("counting through the definer helpers (their owner has BYPASSRLS)", bool(row and row[0]), True)
        connection.rollback()
