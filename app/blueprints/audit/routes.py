"""Audit log viewer (#31).

Administrators only, read-only. There is deliberately no POST, PUT, PATCH or DELETE route in
this blueprint: audit rows are never edited or removed through the app (hard rule 1, and
cds_app has no UPDATE or DELETE on the table at the database level).

Viewing is itself audited, bounded per administrator and filter combination, so paging or
reloading cannot flood the log. The audit detail names the filters used, never their values.
"""

from flask import Blueprint, current_app, render_template, request, url_for
from flask_login import login_required

from app.middleware.rbac import audit_access_denied, require_role
from app.models.user import User
from app.services import audit_view_service as viewer

audit_bp = Blueprint("audit", __name__, template_folder="../../templates")

VIEW_AUDIT_CAP_PER_WINDOW = 20


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@audit_bp.route("/log", methods=["GET"])
@login_required
@require_role("administrator")
def view_log():
    try:
        filters = viewer.parse_filters(request.args)
    except viewer.SearchError as error:
        audit_access_denied("Audit log filter refused", status_code=400, target_record_type="audit_log",
                            action="audit_log_filter_refused", bound_per_target=False)
        response = current_app.make_response((render_template("audit/error.html", message=str(error)), 400))
        return _no_store(response)
    page, per_page = viewer.parse_paging(request.args)
    rows, total = viewer.search(filters, page, per_page)

    used = sorted(filters)
    audit_access_denied("Viewed audit log" + (f" (filters: {', '.join(used)})" if used else ""),
                        status_code=200, target_record_type="audit_log", action="audit_log_viewed",
                        actor_cap=VIEW_AUDIT_CAP_PER_WINDOW)

    filter_args = {name: request.args.get(name) for name in filters}
    last_page = max(1, -(-total // per_page))
    page_url = lambda number: url_for("audit.view_log", page=number, per_page=per_page, **filter_args)  # noqa: E731
    response = current_app.make_response(render_template(
        "audit/log.html",
        rows=rows,
        filters={name: request.args.get(name, "") for name in viewer.FILTER_NAMES},
        actions=viewer.known_actions(),
        record_types=viewer.known_record_types(),
        users=User.query.order_by(User.full_name).all(),
        paging={"page": page, "per_page": per_page, "total": total, "last_page": last_page,
                "options": viewer.PER_PAGE_OPTIONS,
                "prev_url": page_url(page - 1) if page > 1 else None,
                "next_url": page_url(page + 1) if page < last_page else None},
    ))
    return _no_store(response)
