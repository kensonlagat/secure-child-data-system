"""Shared record-list handlers for the school and children's-home blueprints (#32).

The list is always built from access_service.get_accessible_records() (hard rule 2), then
narrowed by app/services/record_search.py. Search terms never appear in URLs, redirects
or audit details.
"""

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from app.middleware.rbac import audit_access_denied
from app.models.child_record import ChildRecord
from app.models.legal_status_change_request import VALID_LEGAL_STATUSES
from app.models.school_class import SchoolClass
from app.services.access_service import get_accessible_records, get_visible_fields, get_writable_fields
from app.services.audit_service import log_action
from app.services.record_search import (
    FILTER_RULES,
    PER_PAGE_OPTIONS,
    SearchError,
    apply_filters,
    clear_name_term,
    get_name_term,
    paginate,
    parse_filters,
    parse_paging,
    set_name_term,
)

MODE_LABELS = {"school": "school mode", "childrens_home": "children's home mode"}


def _wants_html():
    return request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"


def _refuse(mode, error):
    audit_access_denied(f"Record search refused in {MODE_LABELS[mode]}", status_code=400,
                        action="record_search_refused")
    if _wants_html():
        return render_template("records/search_error.html", message=str(error)), 400
    return jsonify({"error": str(error)}), 400


def _allowed_filters(visible_fields, mode):
    return [name for name, (field, modes) in FILTER_RULES.items() if mode in modes and field in visible_fields]


def records_response(mode, *, list_endpoint, edit_endpoint, page_title, page_heading, page_subtitle):
    visible_fields = get_visible_fields(current_user)
    try:
        filters = parse_filters(request.args, visible_fields, mode)
    except SearchError as error:
        return _refuse(mode, error)
    page, per_page = parse_paging(request.args)
    name_term = get_name_term(mode)

    query = apply_filters(get_accessible_records(current_user).filter(ChildRecord.institution_mode == mode), filters)
    records, total = paginate(query, name_term, page, per_page)
    entries = [{
        "record": record,
        "values": {field: getattr(record, field) for field in visible_fields},
        "writable_fields": get_writable_fields(current_user, record),
    } for record in records]

    used = sorted(filters) + (["name"] if name_term else [])
    log_action(user_id=current_user.id, action="view_records", target_record_type="child_record",
               details=f"Viewed scoped {MODE_LABELS[mode]} child records (page {page}"
                       + (f"; filters: {', '.join(used)}" if used else "") + ")")
    if name_term:
        log_action(user_id=current_user.id, action="record_search", target_record_type="child_record",
                   details=f"Name search in {MODE_LABELS[mode]} returned {total} result(s)")

    if not _wants_html():
        return jsonify({"items": [entry["values"] for entry in entries], "page": page, "per_page": per_page,
                        "total": total})

    filter_args = {name: request.args.get(name) for name in filters}
    last_page = max(1, -(-total // per_page))
    page_url = lambda number: url_for(list_endpoint, page=number, per_page=per_page, **filter_args)  # noqa: E731
    return render_template(
        "records/list.html",
        page_title=page_title, page_heading=page_heading, page_subtitle=page_subtitle,
        visible_fields=visible_fields, record_entries=entries,
        edit_url_builder=lambda record_id: url_for(edit_endpoint, record_id=record_id),
        search={
            "mode": mode, "name_term": name_term or "", "can_search_name": "full_name" in visible_fields,
            "allowed_filters": _allowed_filters(visible_fields, mode), "filter_args": filter_args,
            "classes": SchoolClass.query.filter_by(is_active=True).order_by(SchoolClass.name, SchoolClass.stream).all()
            if "class_id" in _allowed_filters(visible_fields, mode) else [],
            "legal_statuses": sorted(VALID_LEGAL_STATUSES),
            "search_url": url_for(f"{list_endpoint.rsplit('.', 1)[0]}.search_records"),
            "clear_url": url_for(f"{list_endpoint.rsplit('.', 1)[0]}.clear_record_search"),
        },
        paging={"page": page, "per_page": per_page, "total": total, "last_page": last_page,
                "options": PER_PAGE_OPTIONS, "prev_url": page_url(page - 1) if page > 1 else None,
                "next_url": page_url(page + 1) if page < last_page else None},
    )


def search_post(mode, list_endpoint):
    """POST then redirect: the name term goes to the session, never into the URL."""
    visible_fields = get_visible_fields(current_user)
    raw_filters = {name: (request.form.get(name) or "").strip() for name in FILTER_RULES
                   if (request.form.get(name) or "").strip()}
    try:
        parse_filters(raw_filters, visible_fields, mode)
        set_name_term(mode, request.form.get("name"), visible_fields)
    except SearchError as error:
        audit_access_denied(f"Record search refused in {MODE_LABELS[mode]}", status_code=400,
                            action="record_search_refused")
        flash(str(error), "error")
        return redirect(url_for(list_endpoint))
    return redirect(url_for(list_endpoint, **raw_filters))


def clear_post(mode, list_endpoint):
    clear_name_term(mode)
    return redirect(url_for(list_endpoint))
