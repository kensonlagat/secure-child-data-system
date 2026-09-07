"""
Application factory for the Secure Child Data Management System.

Why a factory pattern (create_app) instead of a global `app` object:
- Lets us create multiple app instances with different configs (dev, test, prod)
- Avoids circular imports between blueprints and extensions
- Standard Flask best practice for anything beyond a toy script
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

from app.config import config_by_name

# Extensions are instantiated here (unbound), then bound to the app
# inside create_app() via .init_app(). This is what allows the factory
# pattern to work without circular imports.
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()


def create_app(config_name="development"):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Bind extensions to this app instance
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

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

    # RBAC enforcement runs on every request, before it reaches a route.
    # This is what your proposal calls "role enforcement middleware".
    from app.middleware.rbac import register_rbac_hooks
    register_rbac_hooks(app)

    return app
