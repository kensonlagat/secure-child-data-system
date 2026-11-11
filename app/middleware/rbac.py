"""
Role enforcement middleware — this is the piece your System Architecture
diagram shows sitting between authenticated requests and the data/audit
modules. It has two responsibilities:

1. A before_request hook that runs on every request (registered here).
2. A `require_role(*roles)` decorator for fine-grained per-route checks,
   used on top of the coarse before_request pass.

Sprint 2 (RBAC module) is where this gets fully built out. This stub gives
you the hook points so the pattern is established from day one, rather than
bolted on later.
"""
from datetime import datetime, timedelta
from functools import wraps

from flask import abort, current_app, g, request
from flask_login import current_user

# Fixed identifier for refusals with no signed-in user. Never derived from request
# input, so it cannot carry anything an attacker typed.
ANONYMOUS_IDENTIFIER = "anonymous"


def _audit_refusal(status_code):
    """Audit a refused request, bounded so it cannot be used to flood the audit log.

    At most one row per actor, endpoint and outcome in each window
    (ACCESS_DENIED_AUDIT_WINDOW_SECONDS). The actor is the user for signed-in requests.
    Anonymous refusals share one actor per endpoint, so rotating IP addresses does not
    lift the bound. Any failure here is swallowed: the refusal itself must always happen.
    """
    from app import db
    from app.models.audit_log import AuditLogEntry
    from app.services.audit_service import log_action

    try:
        signed_in = current_user.is_authenticated
        user_id = current_user.id if signed_in else None
        details = (
            f"Role check refused for endpoint {request.endpoint}"
            if signed_in
            else f"Unauthenticated request refused for endpoint {request.endpoint}"
        )
        window = timedelta(
            seconds=current_app.config.get("ACCESS_DENIED_AUDIT_WINDOW_SECONDS", 60)
        )
        recent = AuditLogEntry.query.filter(
            AuditLogEntry.action == "access_denied",
            AuditLogEntry.details == details,
            AuditLogEntry.timestamp > datetime.utcnow() - window,
        )
        recent = (
            recent.filter(AuditLogEntry.user_id == user_id)
            if signed_in
            else recent.filter(AuditLogEntry.user_id.is_(None))
        )
        if recent.first() is not None:
            return
        log_action(
            user_id=user_id,
            action="access_denied",
            target_record_type="route",
            details=details,
            attempted_identifier=None if signed_in else ANONYMOUS_IDENTIFIER,
        )
    except Exception:  # noqa: BLE001 - auditing must never stop a refusal
        db.session.rollback()
        current_app.logger.warning(
            "Could not audit a %s refusal for endpoint %s", status_code, request.endpoint
        )


def register_rbac_hooks(app):
    @app.before_request
    def load_current_role():
        # Makes the active user's role available as g.current_role
        # for the rest of the request lifecycle (templates, route logic).
        if current_user.is_authenticated:
            g.current_role = current_user.role.name
        else:
            g.current_role = None


def require_role(*allowed_roles):
    """
    Decorator for route-level access control.

    Usage:
        @school_bp.route("/records")
        @require_role("teacher", "administrator")
        def records():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                _audit_refusal(401)
                abort(401)
            role_name = getattr(current_user.role, "name", None)
            if role_name not in allowed_roles:
                # Audited (bounded), and the 403 happens whether or not the audit works.
                _audit_refusal(403)
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
