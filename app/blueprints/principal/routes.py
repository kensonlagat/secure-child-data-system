"""Principal overview (#53): read-only aggregates for the school. No detail pages link
from here, and nothing on it names a child or shows clinical or concern content."""

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from app.middleware.rbac import require_role
from app.services import overview_service
from app.services.audit_service import log_action

principal_bp = Blueprint("principal", __name__, template_folder="../../templates")


@principal_bp.route("/overview")
@login_required
@require_role("principal", "administrator")
def overview():
    log_action(user_id=current_user.id, action="principal_overview_viewed", target_record_type="route",
               details="Viewed the principal overview (aggregates only)")
    trend = overview_service.attendance_trend()
    peak = max([sum(day.values()) for day in trend.values()] + [1])
    return render_template("principal/overview.html", trend=trend, peak=peak,
                           clinic=overview_service.clinic_activity(),
                           open_concerns=overview_service.open_concerns_count())
