"""
Notification Module (Sprint 6).

Scope per proposal:
- SMS to parents (School Mode) on record access/modification
- OTP delivery for sensitive actions
- Legal officer alerts for upcoming court dates / placement reviews
- Every notification logged
"""
from flask import Blueprint

notifications_bp = Blueprint("notifications", __name__, template_folder="../../templates")


@notifications_bp.route("/log")
def notification_log():
    # TODO (Sprint 6): list of sent notifications
    return "Notifications log placeholder"
