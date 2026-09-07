"""
School Mode Module (Sprint 3).

Scope per proposal:
- Teachers: academic records for their assigned class only
- School Nurse: medical records only
- Admin staff: fee records + general info
- Parents: SMS notification on record access/modification
"""
from flask import Blueprint

school_bp = Blueprint("school_mode", __name__, template_folder="../../templates")


@school_bp.route("/records")
def records():
    # TODO (Sprint 3): role-filtered record list, scoped via RBAC middleware
    return "School mode records placeholder"
