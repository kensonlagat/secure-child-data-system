"""
Application factory for the Secure Child Data Management System.

Why a factory pattern (create_app) instead of a global `app` object:
- Lets us create multiple app instances with different configs (dev, test, prod)
- Avoids circular imports between blueprints and extensions
- Standard Flask best practice for anything beyond a toy script
"""

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFError, CSRFProtect

from app.config import config_by_name

# Extensions are instantiated here (unbound), then bound to the app
# inside create_app() via .init_app(). This is what allows the factory
# pattern to work without circular imports.
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()


@login_manager.user_loader
def load_user(user_id):
    """Resolve a persisted session user ID to a User model instance."""
    from app.models.user import User

    try:
        user = db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
    # A deactivated account is signed out on its very next request (#30): Flask-Login only
    # checks is_active at sign-in, so the session would otherwise outlive deactivation.
    if user is None or not user.is_active:
        return None
    return user


DEFAULT_SECRET_KEY = "change-me-in-env-file"
MIN_SECRET_KEY_LENGTH = 32


def _refuse_weak_or_missing_keys(app):
    """Refuse to start with keys that would make the security controls meaningless (#73).

    - FIELD_ENCRYPTION_KEY missing: refused in every mode except testing (encrypted
      columns cannot work safely without it).
    - SECRET_KEY missing, the default, or short: refused unless debug or testing. With a
      known key, sessions could be forged and audit hashes reversed by guessing emails.
    Messages name the setting, never its value.
    """
    if app.config.get("TESTING"):
        return
    if not (app.config.get("FIELD_ENCRYPTION_KEY") or "").strip():
        raise RuntimeError("FIELD_ENCRYPTION_KEY is not set. Add it to .env before starting the app.")
    if app.debug:
        return
    secret = app.config.get("SECRET_KEY") or ""
    if secret == DEFAULT_SECRET_KEY or len(secret) < MIN_SECRET_KEY_LENGTH:
        raise RuntimeError(
            f"SECRET_KEY is missing, the default, or shorter than {MIN_SECRET_KEY_LENGTH} characters. "
            "Set a long random SECRET_KEY in .env before starting outside debug mode."
        )


def create_app(config_name="development"):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])
    _refuse_weak_or_missing_keys(app)

    # Bind extensions to this app instance
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "auth.login"

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        """Return a safe CSRF failure response for API and form requests."""
        from flask_login import current_user

        if current_user.is_authenticated:
            from app.middleware.rbac import audit_access_denied

            # Bounded like access_denied (#101): one row per user and endpoint per window, and
            # at most CSRF_FAILURE_AUDIT_CAP_PER_WINDOW per user across endpoints. Keyed on the
            # endpoint, not the path, so cycling record ids in the URL can't lift the bound.
            # Never blocks the refusal below.
            audit_access_denied(
                f"CSRF validation failed for endpoint {request.endpoint or 'unknown'}",
                status_code=400,
                action="csrf_failure",
                actor_cap=app.config.get("CSRF_FAILURE_AUDIT_CAP_PER_WINDOW", 20),
            )

        if request.is_json:
            return jsonify({"error": "CSRF validation failed."}), 400

        flash(
            "Your session form token is invalid or has expired. Please try again.",
            "error",
        )
        return redirect(request.referrer or url_for("auth.login"))

    @app.after_request
    def audit_unreadable_encrypted_values(response):
        """One audit row per request in which an encrypted value failed its integrity check
        (#88). Never changes the response, and never records the value."""
        from flask import g

        count = g.pop("unreadable_encrypted_values", 0)
        if count:
            try:
                from flask_login import current_user
                from app.services.audit_service import log_action

                authenticated = current_user.is_authenticated
                log_action(
                    action="encrypted_value_unreadable",
                    user_id=current_user.id if authenticated else None,
                    attempted_identifier=None if authenticated else "anonymous",
                    details=f"{count} encrypted value(s) failed the integrity check on {request.path}",
                )
            except Exception:
                db.session.rollback()
                app.logger.warning("Could not audit an unreadable encrypted value")
        return response

    @app.context_processor
    def inject_active_portal():
        """Expose the portal whose pages a signed-in user sees (display only).

        Staff are always shown their role's own mode. Administrators span both modes,
        so they see the portal they signed in through or last switched to. This never
        changes what the server allows: access_service.py still decides that.
        """
        from flask import session
        from flask_login import current_user

        from app.blueprints.auth.routes import ACTIVE_PORTAL_SESSION_KEY, VALID_PORTALS

        if not current_user.is_authenticated or current_user.role is None:
            return {"active_portal": None}
        role_mode = current_user.role.institution_mode
        if role_mode in VALID_PORTALS:
            return {"active_portal": role_mode}
        chosen = session.get(ACTIVE_PORTAL_SESSION_KEY)
        return {"active_portal": chosen if chosen in VALID_PORTALS else "school"}

    @app.get("/")
    def index():
        """Show the public landing page, or send signed-in users to their landing page."""
        from flask_login import current_user

        if current_user.is_authenticated:
            from app.blueprints.auth.routes import _landing_endpoint_for_user

            return redirect(url_for(_landing_endpoint_for_user(current_user)))
        return render_template("landing.html")

    @app.get("/favicon.ico")
    def favicon():
        """Redirect legacy favicon requests to the SVG favicon asset."""
        return redirect(url_for("static", filename="favicon.svg"))

    # Register blueprints — each module in the proposal maps to one blueprint.
    # Keeping registration here (not scattered) gives us one place to see
    # the whole app's route surface.
    from app.blueprints.auth.routes import auth_bp
    from app.blueprints.admin.routes import admin_bp
    from app.blueprints.school_mode.routes import school_bp
    from app.blueprints.childrens_home_mode.routes import home_bp
    from app.blueprints.audit.routes import audit_bp
    from app.blueprints.notifications.routes import notifications_bp
    from app.blueprints.anomaly.routes import anomaly_bp
    from app.blueprints.consent.routes import consent_bp
    from app.blueprints.attendance.routes import attendance_bp
    from app.blueprints.pickup.routes import pickup_bp
    from app.blueprints.clinic.routes import clinic_bp
    from app.blueprints.intake.routes import intake_bp
    from app.blueprints.care.routes import care_bp
    from app.blueprints.court.routes import court_bp
    from app.blueprints.health.routes import health_bp
    from app.blueprints.principal.routes import principal_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(school_bp, url_prefix="/school")
    app.register_blueprint(home_bp, url_prefix="/home-mode")
    app.register_blueprint(audit_bp, url_prefix="/audit")
    app.register_blueprint(notifications_bp, url_prefix="/notifications")
    app.register_blueprint(anomaly_bp, url_prefix="/anomaly")
    app.register_blueprint(consent_bp, url_prefix="/consent")
    app.register_blueprint(attendance_bp, url_prefix="/attendance")
    app.register_blueprint(pickup_bp, url_prefix="/pickup")
    app.register_blueprint(clinic_bp, url_prefix="/clinic")
    app.register_blueprint(intake_bp, url_prefix="/intake")
    app.register_blueprint(care_bp, url_prefix="/care")
    app.register_blueprint(court_bp, url_prefix="/court")
    app.register_blueprint(health_bp, url_prefix="/health")
    app.register_blueprint(principal_bp, url_prefix="/principal")

    # Register trusted local CLI bootstrap commands (roles + first admin).
    from app.cli import register_cli_commands

    register_cli_commands(app)

    # RBAC enforcement runs on every request, before it reaches a route.
    # This is what your proposal calls "role enforcement middleware".
    from app.middleware.rbac import register_rbac_hooks

    register_rbac_hooks(app)

    return app
