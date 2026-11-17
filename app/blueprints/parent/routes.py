"""Parent portal (#67): its own sign-in (phone plus one-time code) and its own pages.

- Both sign-in steps answer identically for every input, with a 2-second response floor, so a
  phone number can't be tested for registration (hard rule 7).
- Pages need the parent_guardian role. They show only children with an active link, and only
  the minimal fields. Staff routes refuse parent accounts (see register_parent_guard).
"""

import time

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user

from app.middleware.rbac import audit_access_denied, require_role
from app.models.child_record import ChildRecord
from app.services import parent_service
from app.services.access_service import get_accessible_records, get_visible_fields
from app.services.attendance_service import absences_in_window
from app.services.audit_service import log_action
from app.services.consent_service import current as current_consent

parent_bp = Blueprint("parent", __name__, template_folder="../../templates")

MIN_RESPONSE_SECONDS = 2.0
REQUEST_MESSAGE = "If this number is registered, we have sent a code. It expires in 5 minutes."
VERIFY_ERROR = "That code didn't work or has expired. Request a new code and try again."
PENDING_PHONE_KEY = "parent_pending_phone"
ATTENDANCE_WINDOW_DAYS = 30


def _floor(started):
    elapsed = time.monotonic() - started
    if elapsed < MIN_RESPONSE_SECONDS:
        time.sleep(MIN_RESPONSE_SECONDS - elapsed)


def _payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else request.form


@parent_bp.route("/login", methods=["GET"])
def login_form():
    if current_user.is_authenticated and getattr(current_user.role, "name", None) == "parent_guardian":
        return redirect(url_for("parent.home"))
    return render_template("parent/login.html")


@parent_bp.route("/login", methods=["POST"])
def login():
    started = time.monotonic()
    raw_phone = _payload().get("phone")
    raw_phone = raw_phone[:40] if isinstance(raw_phone, str) else ""
    parent_service.request_code(raw_phone, request.remote_addr)
    session[PENDING_PHONE_KEY] = raw_phone
    _floor(started)
    if request.is_json:
        return jsonify({"message": REQUEST_MESSAGE}), 200
    return redirect(url_for("parent.verify_form"))


@parent_bp.route("/verify", methods=["GET"])
def verify_form():
    if not session.get(PENDING_PHONE_KEY):
        return redirect(url_for("parent.login_form"))
    return render_template("parent/verify.html", message=REQUEST_MESSAGE)


@parent_bp.route("/verify", methods=["POST"])
def verify():
    started = time.monotonic()
    payload = _payload()
    raw_phone = payload.get("phone") if request.is_json else session.get(PENDING_PHONE_KEY)
    raw_phone = raw_phone[:40] if isinstance(raw_phone, str) else ""
    parent = parent_service.verify_code(raw_phone, payload.get("code"), request.remote_addr)
    if parent is None:
        _floor(started)
        if request.is_json:
            return jsonify({"error": VERIFY_ERROR}), 401
        return render_template("parent/verify.html", error=VERIFY_ERROR), 401
    session.clear()  # nothing from before sign-in carries over
    login_user(parent, remember=False, fresh=True)
    log_action(user_id=parent.id, action="parent_login_succeeded", target_record_type="user",
               target_record_id=parent.id, details="Parent signed in with a phone code")
    _floor(started)
    if request.is_json:
        return jsonify({"status": "signed_in"}), 200
    return redirect(url_for("parent.home"))


def _wants_json():
    return request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json"


@parent_bp.route("/")
@login_required
@require_role("parent_guardian")
def home():
    children = get_accessible_records(current_user).order_by(ChildRecord.id).all()
    fields = get_visible_fields(current_user)
    log_action(user_id=current_user.id, action="parent_viewed_children", target_record_type="user",
               target_record_id=current_user.id, details=f"Parent viewed {len(children)} linked child(ren)")
    if _wants_json():
        return jsonify({"items": [{field: getattr(child, field) for field in fields} for child in children]})
    return render_template("parent/home.html", children=children)


@parent_bp.route("/children/<int:record_id>")
@login_required
@require_role("parent_guardian")
def child(record_id):
    record = get_accessible_records(current_user).filter(ChildRecord.id == record_id).first()
    if record is None:
        # Unlinked, pending, revoked, archived or missing: all the same 404, audited (bounded).
        audit_access_denied("Parent denied child view", status_code=404, target_record_type="child_record",
                            target_record_id=record_id,
                            actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
        if _wants_json():
            return jsonify({"error": "Not found"}), 404
        abort(404)
    values = {field: getattr(record, field) for field in get_visible_fields(current_user)}
    consent = {consent_type: (entry.status if entry else "not_recorded")
               for consent_type, entry in current_consent(record.id).items()}
    absences = absences_in_window(record.id, ATTENDANCE_WINDOW_DAYS)
    audit_access_denied("Parent viewed linked child", status_code=200, target_record_type="child_record",
                        target_record_id=record.id, action="parent_viewed_child")
    if _wants_json():
        return jsonify({**values, "absences_last_30_days": absences, "consent": consent})
    return render_template("parent/child.html", values=values, consent=consent, absences=absences,
                           window=ATTENDANCE_WINDOW_DAYS)


# Parent accounts may use only these endpoints. Everything else (every staff page and API)
# answers 403, audited (bounded), even where a staff route would otherwise rely on
# access_service scoping alone. Fail closed: a new staff route is covered automatically.
PARENT_ALLOWED_ENDPOINTS = {"static", "auth.logout", "index"}


def register_parent_guard(app):
    @app.before_request
    def refuse_staff_routes_for_parents():
        if not current_user.is_authenticated or getattr(current_user.role, "name", None) != "parent_guardian":
            return None
        endpoint = request.endpoint or ""
        if endpoint.startswith("parent.") or endpoint in PARENT_ALLOWED_ENDPOINTS or not endpoint:
            return None
        audit_access_denied(f"Parent account refused staff endpoint {endpoint}", status_code=403)
        if _wants_json():
            return jsonify({"error": "Forbidden"}), 403
        abort(403)
