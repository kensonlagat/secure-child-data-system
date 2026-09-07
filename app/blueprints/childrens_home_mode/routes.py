"""
Children's Home Mode Module (Sprint 4).

Scope per proposal:
- Social workers: welfare records for their caseload only
- Legal officers: legal status, court dates, guardianship
- Legal status changes require two-person approval before saving
- Optional academic module for homes running internal schools
"""
from flask import Blueprint

home_bp = Blueprint("childrens_home_mode", __name__, template_folder="../../templates")


@home_bp.route("/records")
def records():
    # TODO (Sprint 4): caseload-scoped record list
    return "Children's home mode records placeholder"


@home_bp.route("/legal-status/<int:record_id>/request-change", methods=["POST"])
def request_legal_status_change(record_id):
    # TODO (Sprint 4): create a pending change requiring second approver + OTP
    return "Legal status change workflow placeholder"
