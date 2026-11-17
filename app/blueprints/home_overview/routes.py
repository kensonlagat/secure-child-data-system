"""Home manager overview (#61): read-only counts and due items for the children's home.
Every item links only to pages the home manager's role can already open."""

from datetime import date

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from app.middleware.rbac import require_role
from app.models.care_plan import CarePlanGoal
from app.models.child_record import ChildRecord
from app.services import court_service, missing_service, placement_service
from app.services.access_service import get_accessible_records
from app.services.audit_service import log_action

home_overview_bp = Blueprint("home_overview", __name__, template_folder="../../templates")


@home_overview_bp.route("/overview")
@login_required
@require_role("home_manager", "administrator")
def overview():
    records = get_accessible_records(current_user).filter(ChildRecord.institution_mode == "childrens_home")
    record_ids = [r.id for r in records.with_entities(ChildRecord.id)]
    hearings = court_service.upcoming(record_ids) if record_ids else []
    overdue_goals = (CarePlanGoal.query.filter(CarePlanGoal.child_record_id.in_(record_ids), CarePlanGoal.status == "open",
                                               CarePlanGoal.review_date < date.today())
                     .order_by(CarePlanGoal.review_date).all()) if record_ids else []
    alerts = [a for a in missing_service.open_alerts() if a.child_record_id in record_ids]
    aftercare = placement_service.due_followups(record_ids) if record_ids else []
    log_action(user_id=current_user.id, action="home_overview_viewed", target_record_type="route",
               details="Viewed the home manager overview (counts and due items)")
    return render_template("home_overview/overview.html", occupancy=len(record_ids), hearings=hearings,
                           overdue_goals=overdue_goals, alerts=alerts, aftercare=aftercare)
