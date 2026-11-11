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


def audit_access_denied(
    details,
    *,
    status_code,
    target_record_type="route",
    target_record_id=None,
    action="access_denied",
    bound_per_target=True,
):
    """Write a bounded refusal audit row (access_denied by default). Shared by role checks
    and record checks; record checks also use it for record_not_found.

    bound_per_target=False bounds per actor only (the row still records the first target),
    for refusals whose targets are unlimited, such as IDs that do not exist.

    At most one row per actor, target and refusal in each window
    (ACCESS_DENIED_AUDIT_WINDOW_SECONDS), so hammering a protected URL or record cannot
    flood the audit log. The actor is the user for signed-in requests. Anonymous refusals
    share one actor per target, so rotating IP addresses does not lift the bound. Any
    failure here is swallowed: the caller's refusal must always happen.
    """
    from app import db
    from app.models.audit_log import AuditLogEntry
    from app.services.audit_service import log_action

    try:
        signed_in = current_user.is_authenticated
        user_id = current_user.id if signed_in else None
        window = timedelta(
            seconds=current_app.config.get("ACCESS_DENIED_AUDIT_WINDOW_SECONDS", 60)
        )
        recent = AuditLogEntry.query.filter(
            AuditLogEntry.action == action,
            AuditLogEntry.details == details,
            AuditLogEntry.target_record_type == target_record_type,
            AuditLogEntry.timestamp > datetime.utcnow() - window,
        )
        if bound_per_target:
            recent = recent.filter(
                AuditLogEntry.target_record_id == target_record_id
                if target_record_id is not None
                else AuditLogEntry.target_record_id.is_(None)
            )
        recent = recent.filter(
            AuditLogEntry.user_id == user_id if signed_in else AuditLogEntry.user_id.is_(None)
        )
        if recent.first() is not None:
            return
        log_action(
            user_id=user_id,
            action=action,
            target_record_type=target_record_type,
            target_record_id=target_record_id,
            details=details,
            attempted_identifier=None if signed_in else ANONYMOUS_IDENTIFIER,
        )
    except Exception:  # noqa: BLE001 - auditing must never stop a refusal
        db.session.rollback()
        current_app.logger.warning(
            "Could not audit a %s refusal for endpoint %s", status_code, request.endpoint
        )


def _audit_refusal(status_code):
    """Audit a refused role check (bounded, never blocks the refusal)."""
    signed_in = current_user.is_authenticated
    details = (
        f"Role check refused for endpoint {request.endpoint}"
        if signed_in
        else f"Unauthenticated request refused for endpoint {request.endpoint}"
    )
    audit_access_denied(details, status_code=status_code)


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
