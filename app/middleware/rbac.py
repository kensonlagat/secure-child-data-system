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
from functools import wraps
from flask import abort, g, request
from flask_login import current_user


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
                abort(401)
            role_name = getattr(current_user.role, "name", None)
            if role_name not in allowed_roles:
                # Every role-check refusal is audited (fail closed, never silently).
                from app.services.audit_service import log_action

                log_action(
                    user_id=current_user.id,
                    action="access_denied",
                    target_record_type="route",
                    details=f"Role check refused for endpoint {request.endpoint}",
                )
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
