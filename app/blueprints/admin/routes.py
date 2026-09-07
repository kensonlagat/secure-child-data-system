"""
Administrator Module (built alongside other sprints, primarily Sprint 2+).

Scope per proposal:
- Register users, assign roles
- Configure institution mode (School / Children's Home) + optional academic module
- Full audit log access
- Manage role permissions, deactivate accounts
"""
from flask import Blueprint

admin_bp = Blueprint("admin", __name__, template_folder="../../templates")


@admin_bp.route("/dashboard")
def dashboard():
    # TODO: consolidate user management, audit log access, anomaly alerts
    return "Admin dashboard placeholder"
