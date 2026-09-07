"""
Audit Logging Module (Sprint 5).

Scope per proposal:
- Auto-record every access/modification/creation/deletion event
- Entries immutable — enforced at DB layer via insert-only rule/trigger
- Admin can filter/search by user, date, action type, record
"""
from flask import Blueprint

audit_bp = Blueprint("audit", __name__, template_folder="../../templates")


@audit_bp.route("/log")
def view_log():
    # TODO (Sprint 5): filterable audit log view for administrators
    return "Audit log placeholder"
