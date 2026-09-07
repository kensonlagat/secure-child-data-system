"""
Anomaly Detection Module (Sprint 7).

Scope per proposal:
- Isolation Forest (scikit-learn) trained on audit log data, per-role baseline
- Flags: off-hours access, bulk export, out-of-caseload access, repeated
  failed OTP attempts
- Alert-only — surfaces to admin dashboard, never blocks autonomously
"""
from flask import Blueprint

anomaly_bp = Blueprint("anomaly", __name__, template_folder="../../templates")


@anomaly_bp.route("/alerts")
def alerts():
    # TODO (Sprint 7): list of flagged anomaly events for admin review
    return "Anomaly alerts placeholder"
