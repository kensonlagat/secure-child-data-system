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
MIGRATION_TABLE = "alembic_version"
PURGE_FUNCTION = "purge_synthetic_audit_entries()"


def validate_role_name(name):
    """Reject anything that is not a plain lower-case PostgreSQL identifier."""
    if not ROLE_NAME_PATTERN.fullmatch(name or ""):
        raise ValueError(f"Invalid role name: {name!r}")
    return name


def _role_exists(cursor, name):
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,))
    return cursor.fetchone() is not None


def _ensure_login_role(cursor, name, password):
    """Create the role (or update its password) with no special privileges."""
    attributes = sql.SQL("LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
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


def setup_roles(dsn, owner_role, app_role, owner_password=None, app_password=None):
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

                steps.append(f"owner role {owner_role}: {_ensure_login_role(cursor, owner_role, owner_password)}")
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
                    if table == MIGRATION_TABLE:
                        continue  # the app never touches migration state
                    privileges = (
                        sql.SQL("SELECT, INSERT")
                        if table == AUDIT_TABLE
                        else sql.SQL("SELECT, INSERT, UPDATE")
                    )
                    cursor.execute(
                        sql.SQL("GRANT {} ON public.{} TO {}").format(privileges, sql.Identifier(table), app)
                    )
                cursor.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(app))
                steps.append(
                    f"{app_role}: SELECT, INSERT, UPDATE on app tables; SELECT, INSERT only on "
                    f"{AUDIT_TABLE}; nothing on {MIGRATION_TABLE}; no DELETE or TRUNCATE anywhere"
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


def check_privileges(dsn):
    """Connect as the configured app role and prove the restrictions. Returns (ok, lines)."""
    lines, ok = [], True
    connection = psycopg2.connect(dsn)
    try:
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

        attempt("SELECT on audit_log_entries", "SELECT count(*) FROM audit_log_entries", True)
        attempt(
            "INSERT into audit_log_entries",
            "INSERT INTO audit_log_entries (action, attempted_identifier, is_synthetic) "
            "VALUES ('privilege_check', 'privilege-check', true)",
            True,
        )
        attempt("UPDATE on audit_log_entries", "UPDATE audit_log_entries SET details = details WHERE false", False)
        attempt("DELETE on audit_log_entries", "DELETE FROM audit_log_entries WHERE false", False)
        has_privilege("TRUNCATE on audit_log_entries", AUDIT_TABLE, "TRUNCATE", False)
        attempt("DELETE on child_records", "DELETE FROM child_records WHERE false", False)
        attempt("UPDATE on child_records", "UPDATE child_records SET id = id WHERE false", True)
        attempt("UPDATE on alembic_version", "UPDATE alembic_version SET version_num = version_num WHERE false", False)
        attempt("CREATE TABLE", "CREATE TABLE privilege_check_probe (id integer)", False)
        attempt("purge_synthetic_audit_entries()", "SELECT purge_synthetic_audit_entries()", True)
    finally:
        connection.close()
    return ok, lines
