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
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def create_app(config_name="development"):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

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
            from app.services.audit_service import log_action

            log_action(
                user_id=current_user.id,
                action="csrf_failure",
                details=f"CSRF validation failed for {request.path}",
            )

        if request.is_json:
            return jsonify({"error": "CSRF validation failed."}), 400

        flash(
            "Your session form token is invalid or has expired. Please try again.",
            "error",
        )
        return redirect(request.referrer or url_for("auth.login"))

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

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(school_bp, url_prefix="/school")
    app.register_blueprint(home_bp, url_prefix="/home-mode")
    app.register_blueprint(audit_bp, url_prefix="/audit")
    app.register_blueprint(notifications_bp, url_prefix="/notifications")
    app.register_blueprint(anomaly_bp, url_prefix="/anomaly")

    # Register trusted local CLI bootstrap commands (roles + first admin).
    from app.cli import register_cli_commands

    register_cli_commands(app)

    # RBAC enforcement runs on every request, before it reaches a route.
    # This is what your proposal calls "role enforcement middleware".
    from app.middleware.rbac import register_rbac_hooks

    register_rbac_hooks(app)

    return app
