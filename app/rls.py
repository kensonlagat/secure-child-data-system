"""Row-level security context (#19).

At the start of every database transaction on PostgreSQL, the app sets transaction-local
settings (set_config(..., true), so nothing leaks to the next transaction on a pooled
connection):

    app.user_id, app.role, app.mode, app.issued_at, app.context_sig

The signature is an HMAC-SHA256, under the #73 subkey `rls-context`, of
"user_id|role|mode|issued_at|pid", where pid is the PostgreSQL backend process id of the
connection the context is set on. The database recomputes it in app_context_valid() with the
copy of the key that `flask setup-db-roles` stores in an owner-only table and its OWN
pg_backend_pid(), and refuses a context that is unsigned, forged, older than 5 minutes, or
copied from another connection. Injected SQL can call set_config, but without the key it can't
produce a valid signature, so it sees no rows. Binding to the pid matters because every app
connection runs as cds_app, and a role can read pg_stat_activity.query for its own other
sessions, which can show another request's set_config call with its live signature.

The pid is read once per physical connection and cached in connection.info. This assumes each
app connection is a real backend (no transaction-pooling proxy such as PgBouncer in
transaction mode, which would change the backend under the app: contexts would then fail
closed, showing no rows).

Who the request is comes from the server's own state, never from request input:
- a signed-in request: Flask-Login's user id in the signed session cookie, with the role read
  from the database (inactive accounts count as anonymous);
- an explicit `system_context()` block, used only by CLI commands (D19.3);
- anything else: `anonymous`, which sees no child rows and may only insert audit rows.
"""

import hashlib
import hmac
import time
from contextlib import contextmanager

from flask import current_app, g, has_app_context, has_request_context, session
from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.services.key_derivation import derive_subkey

SETTINGS = ("app.user_id", "app.role", "app.mode", "app.issued_at", "app.context_sig")


def sign(user_id, role, mode, issued_at, pid):
    message = f"{user_id}|{role}|{mode}|{issued_at}|{pid}".encode()
    return hmac.new(derive_subkey("rls-context"), message, hashlib.sha256).hexdigest()


def context_values(user_id, role, mode, *, pid, issued_at=None):
    """pid: pg_backend_pid() of the connection the context will be set on (required)."""
    issued_at = str(int(issued_at if issued_at is not None else time.time()))
    user_id, mode = str(user_id or ""), mode or ""
    return {"app.user_id": user_id, "app.role": role, "app.mode": mode, "app.issued_at": issued_at,
            "app.context_sig": sign(user_id, role, mode, issued_at, int(pid))}


def backend_pid(connection):
    """pg_backend_pid() for this physical connection, read once and cached in connection.info
    (which lives as long as the pooled DBAPI connection)."""
    pid = connection.info.get("rls_backend_pid")
    if pid is None:
        pid = int(connection.execute(text("SELECT pg_backend_pid()")).scalar())
        connection.info["rls_backend_pid"] = pid
    return pid


def apply_context(connection, values):
    """Set the settings for the current transaction only."""
    connection.execute(
        text("SELECT set_config('app.user_id', :u, true), set_config('app.role', :r, true), "
             "set_config('app.mode', :m, true), set_config('app.issued_at', :i, true), "
             "set_config('app.context_sig', :s, true)"),
        {"u": values["app.user_id"], "r": values["app.role"], "m": values["app.mode"],
         "i": values["app.issued_at"], "s": values["app.context_sig"]})


@contextmanager
def system_context():
    """For CLI commands only: database work inside this block runs as the signed `system` role."""
    previous = g.get("rls_system", False)
    g.rls_system = True
    try:
        yield
    finally:
        g.rls_system = previous


def _signed_in_identity(connection):
    if not has_request_context():
        return None
    raw_id = session.get("_user_id")
    if raw_id is None or not str(raw_id).isdigit():
        return None
    row = connection.execute(
        text("SELECT u.id, r.name, r.institution_mode FROM users u JOIN roles r ON r.id = u.role_id "
             "WHERE u.id = :id AND u.is_active"), {"id": int(raw_id)}).first()
    return (row[0], row[1], row[2]) if row else None


def current_identity(connection):
    if has_app_context() and g.get("rls_system", False) and not has_request_context():
        return ("", "system", "")
    identity = _signed_in_identity(connection)
    return identity if identity else ("", "anonymous", "")


def _after_begin(session_, transaction, connection):
    if connection.dialect.name != "postgresql" or not has_app_context():
        return
    if not current_app.config.get("RLS_CONTEXT_ENABLED", True):
        return
    user_id, role, mode = current_identity(connection)
    apply_context(connection, context_values(user_id, role, mode, pid=backend_pid(connection)))


def register_rls_context():
    if not event.contains(Session, "after_begin", _after_begin):
        event.listen(Session, "after_begin", _after_begin)
