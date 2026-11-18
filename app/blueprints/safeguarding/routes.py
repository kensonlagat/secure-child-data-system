"""Safeguarding concerns (#62).

- /concerns/new, /concerns/mine: any active staff member. A reporter sees their own concerns'
  status and time only, never the narrative (not even their own after submitting).
- /safeguarding/concerns[...]: safeguarding leads of the concern's mode only; the detail page is
  the only place the narrative is decrypted, and every read is audited (never bounded).
- /admin/concerns: administrators, metadata only (HTML and JSON from the same field list).
Anyone else, or a concern outside scope: 404, with the real reason audited (bounded).
Parents never reach any of this: the parent guard refuses every endpoint outside parent.*.
"""

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied, require_role
from app.models.child_record import ChildRecord
from app.models.safeguarding import CONCERN_MODES, REFERRAL_AGENCIES, URGENCIES, SafeguardingConcern
from app.services import safeguarding_service as concerns
from app.services.access_service import (
    CONCERN_RAISER_ROLES,
    can_act_on_concern,
    can_raise_concern_about,
    can_read_concern,
    get_accessible_records,
    safeguarding_lead_modes,
)
from app.services.audit_service import log_action

safeguarding_bp = Blueprint("safeguarding", __name__, template_folder="../../templates")


def _wants_json():
    return request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json"


def _deny(details, target_type="safeguarding_concern", target_id=None):
    audit_access_denied(details, status_code=404, target_record_type=target_type, target_record_id=target_id,
                        actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
    abort(404)


def _concern_for_lead(concern_id):
    concern = db.session.get(SafeguardingConcern, concern_id)
    if not can_read_concern(current_user, concern):
        _deny("Denied safeguarding concern access", target_id=concern_id)
    return concern


def _own_mode():
    mode = getattr(current_user.role, "institution_mode", None)
    return mode if mode in CONCERN_MODES else None


def _no_lead_modes_for_user():
    missing = concerns.modes_without_lead()
    mode = _own_mode()
    return missing if mode is None else [m for m in missing if m == mode]


# --- Raising (any staff member) ------------------------------------------------------------------


@safeguarding_bp.route("/concerns/new", methods=["GET"])
@login_required
@require_role(*sorted(CONCERN_RAISER_ROLES))
def new_concern():
    records = get_accessible_records(current_user).order_by(ChildRecord.id).all()
    return render_template("safeguarding/new.html", records=records, urgencies=URGENCIES, own_mode=_own_mode(),
                           modes=CONCERN_MODES, mode_labels=concerns.MODE_LABELS,
                           no_lead_modes=_no_lead_modes_for_user())


@safeguarding_bp.route("/concerns/new", methods=["POST"])
@login_required
@require_role(*sorted(CONCERN_RAISER_ROLES))
def raise_concern():
    raw_child = (request.form.get("child_record_id") or "").strip()
    record = None
    if raw_child:
        record = db.session.get(ChildRecord, int(raw_child)) if raw_child.isdigit() else None
        if not can_raise_concern_about(current_user, record):
            _deny("Denied raising a concern about this record", target_type="child_record",
                  target_id=int(raw_child) if raw_child.isdigit() else None)
    mode = record.institution_mode if record else (_own_mode() or request.form.get("institution_mode"))
    try:
        concerns.raise_concern(current_user, record, mode, request.form)
    except concerns.ConcernError as error:
        db.session.rollback()
        flash(str(error), "error")
        return redirect(url_for("safeguarding.new_concern"))
    if mode in concerns.modes_without_lead():
        flash("Your concern is saved. No safeguarding lead is set up for this mode yet, so administrators "
              "have been told it is waiting.", "info")
    else:
        flash("Your concern has been sent to the safeguarding lead.", "success")
    return redirect(url_for("safeguarding.my_concerns"))


@safeguarding_bp.route("/concerns/mine")
@login_required
@require_role(*sorted(CONCERN_RAISER_ROLES))
def my_concerns():
    mine = concerns.own_concerns(current_user)
    log_action(user_id=current_user.id, action="concern_metadata_viewed", target_record_type="route",
               details=f"Viewed own concerns: {len(mine)}")
    items = [{"id": c.id, "raised_at": c.created_at.isoformat(timespec="minutes"), "status": c.status,
              "mode": c.institution_mode} for c in mine]
    if _wants_json():
        return jsonify({"items": items})
    return render_template("safeguarding/mine.html", items=items, mode_labels=concerns.MODE_LABELS,
                           no_lead_modes=concerns.modes_without_lead())


# --- Leads -----------------------------------------------------------------------------------------


@safeguarding_bp.route("/safeguarding/concerns")
@login_required
def lead_list():
    modes = safeguarding_lead_modes(current_user)
    if not modes:
        _deny("Denied safeguarding concern list", target_type="route")
    queue = concerns.lead_queue(current_user, modes)
    log_action(user_id=current_user.id, action="concern_metadata_viewed", target_record_type="route",
               details=f"Viewed safeguarding queue: {len(queue)}")
    return render_template("safeguarding/lead_list.html", queue=queue, mode_labels=concerns.MODE_LABELS)


@safeguarding_bp.route("/safeguarding/concerns/<int:concern_id>")
@login_required
def lead_detail(concern_id):
    concern = _concern_for_lead(concern_id)
    narrative, actions = concerns.read_for_lead(current_user, concern)
    response = render_template("safeguarding/lead_detail.html", concern=concern, narrative=narrative,
                               actions=actions, child_name=concerns.child_name(concern),
                               next_statuses=concerns.STATUS_FLOW.get(concern.status, ()),
                               agencies=REFERRAL_AGENCIES, mode_labels=concerns.MODE_LABELS,
                               unreadable=concerns.UNREADABLE)
    return response, 200, {"Cache-Control": "no-store"}


@safeguarding_bp.route("/safeguarding/concerns/<int:concern_id>/actions", methods=["POST"])
@login_required
def add_action(concern_id):
    concern = _concern_for_lead(concern_id)
    if not can_act_on_concern(current_user, concern):  # same rule today; kept explicit
        _deny("Denied acting on a safeguarding concern", target_id=concern_id)
    try:
        concerns.add_action(current_user, concern, request.form)
        flash("Recorded.", "success")
    except concerns.ConcernError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("safeguarding.lead_detail", concern_id=concern_id))


@safeguarding_bp.route("/safeguarding/concerns/<int:concern_id>/link", methods=["POST"])
@login_required
def link_child(concern_id):
    concern = _concern_for_lead(concern_id)
    try:
        concerns.link_child(current_user, concern, request.form.get("child_record_id"))
        flash("Child linked.", "success")
    except concerns.ConcernError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("safeguarding.lead_detail", concern_id=concern_id))


# --- Administrators: metadata only ------------------------------------------------------------------


@safeguarding_bp.route("/admin/concerns")
@login_required
@require_role("administrator")
def admin_concerns():
    rows = concerns.admin_rows()
    untriaged = concerns.untriaged_counts()
    no_lead = concerns.modes_without_lead()
    log_action(user_id=current_user.id, action="concern_metadata_viewed", target_record_type="route",
               details=f"Viewed concern metadata: {len(rows)}")
    if _wants_json():
        return jsonify({"items": rows, "untriaged_over_24h": untriaged, "modes_without_lead": no_lead})
    return render_template("safeguarding/admin_list.html", rows=rows, untriaged=untriaged, no_lead=no_lead,
                           mode_labels=concerns.MODE_LABELS)
