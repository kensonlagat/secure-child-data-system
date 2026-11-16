"""Authentication routes for Sprint 1 registration and login."""
import re
import time
from datetime import datetime, timedelta
from typing import Optional

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func

from app import db
from app.middleware.rbac import require_role
from app.models.audit_log import AuditLogEntry
from app.models.otp_event import OTPEvent
from app.models.user import User
from app.services.audit_service import log_action
from app.services.key_derivation import keyed_hash
from app.services.otp_service import generate_otp, verify_otp

auth_bp = Blueprint("auth", __name__, template_folder="../../templates")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
FORGOT_PASSWORD_GENERIC_MESSAGE = "If that email exists, a reset code has been sent."
RESET_PASSWORD_GENERIC_ERROR = "Unable to reset password."
# Enforces a fixed response-time floor for password-reset requests so response
# time is independent of whether the account exists. Must stay above the
# worst-case SMS API latency to prevent timing-based user enumeration.
MIN_RESPONSE_SECONDS = 2.0
GENERIC_LOGIN_ERROR = "Invalid credentials, or too many attempts. Try again later."
# These messages are shown only after the password has verified, so they reveal
# nothing to someone who does not already hold the account's credentials.
INACTIVE_ACCOUNT_ERROR = "This account has been deactivated. Contact your administrator."
PORTAL_MISMATCH_ERROR = (
    "This account doesn't belong to the selected portal. "
    "Choose the other portal and try again."
)
PARENT_ACCOUNT_ERROR = "Parent accounts use the parent sign-in."
# Session key for the portal the user signed in through. Display only: it decides which
# mode the pages show, never what the server allows (access_service.py does that).
ACTIVE_PORTAL_SESSION_KEY = "active_portal"
VALID_PORTALS = {"school", "childrens_home"}
DUMMY_PASSWORD_HASH = generate_password_hash("unusable-login-password")


def _is_valid_email(email: Optional[str]) -> bool:
    """Return True when an email matches a basic valid format."""
    return bool(email and EMAIL_REGEX.match(email))


def _normalize_email(value) -> str:
    """Trim and lower-case a submitted email. Login, forgot and reset all use this, and
    look accounts up with lower(email), so the same address always matches (#74)."""
    return value.strip().lower() if isinstance(value, str) else ""


def _is_valid_password(password: Optional[str]) -> bool:
    """Return True when a password meets minimum length requirements."""
    return bool(password and len(password) >= MIN_PASSWORD_LENGTH)


def _get_payload_value(payload: dict, key: str) -> Optional[str]:
    """Normalize text fields from JSON/form payloads."""
    value = payload.get(key)
    if isinstance(value, str):
        return value.strip()
    return value


def _request_payload():
    """Return the request's JSON object, or the form for anything else.

    A JSON body that is not an object (a list, a string, a number) falls back to the
    form instead of crashing, so every auth endpoint still answers generically and audits.
    """
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return payload
    return request.form


def _audit_identifier(email, user):
    """Return the identifier stored on pre-authentication audit rows.

    Known account: the normalised email (the row also carries the user_id).
    Unknown account: a keyed hash of what was typed. Lockout can still count repeat
    attempts, but the raw text is never stored, because people sometimes type their
    password into the email box (hard rule 1: never log passwords).
    """
    if user is not None:
        return email
    # Keyed with a subkey, never SECRET_KEY itself (#73).
    digest = keyed_hash("audit-identifier", email or "")
    return f"unknown:{digest[:40]}"


def _login_failure_response():
    """Return the generic login failure response for form and JSON clients."""
    if request.is_json:
        return jsonify({"error": GENERIC_LOGIN_ERROR}), 401
    return render_template("auth/login.html", error=GENERIC_LOGIN_ERROR), 401


def _login_denied_response(message):
    """Return a specific denial shown only after the password has verified."""
    if request.is_json:
        return jsonify({"error": message}), 401
    return render_template("auth/login.html", error=message), 401


def _login_lockout_state(identifier, user, remote_addr):
    """Return whether the submitted email or source IP is currently locked out."""
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=current_app.config["LOGIN_LOCKOUT_MINUTES"])
    cutoff = window_start

    if user is not None:
        latest_successful_login = (
            AuditLogEntry.query.filter_by(user_id=user.id, action="login")
            .order_by(AuditLogEntry.timestamp.desc(), AuditLogEntry.id.desc())
            .first()
        )
        if latest_successful_login and latest_successful_login.timestamp:
            cutoff = max(cutoff, latest_successful_login.timestamp)

    email_failures = AuditLogEntry.query.filter(
        AuditLogEntry.action == "login_failed",
        AuditLogEntry.attempted_identifier == identifier,
        AuditLogEntry.timestamp > cutoff,
    ).count()
    ip_failures = AuditLogEntry.query.filter(
        AuditLogEntry.action == "login_failed",
        AuditLogEntry.ip_address == remote_addr,
        AuditLogEntry.timestamp > window_start,
    ).count()

    return (
        email_failures >= current_app.config["LOGIN_MAX_FAILURES"]
        or ip_failures >= current_app.config["LOGIN_IP_MAX_FAILURES"]
    )


def _log_login_failure(identifier, user, details):
    """Audit one failed login attempt with a normalized, bounded identifier."""
    log_action(
        user_id=user.id if user is not None else None,
        action="login_failed",
        target_record_type="user" if user is not None else None,
        target_record_id=user.id if user is not None else None,
        details=details,
        attempted_identifier=identifier,
    )


def _landing_endpoint_for_user(user: User) -> str:
    """Route authenticated users to the most relevant landing page."""
    role_name = getattr(getattr(user, "role", None), "name", None)
    institution_mode = getattr(getattr(user, "role", None), "institution_mode", None)

    if role_name == "administrator":
        return "admin.dashboard"
    if role_name in {"teacher", "school_nurse"} or institution_mode == "school":
        return "school_mode.records"
    if role_name in {"social_worker", "legal_officer"} or institution_mode == "childrens_home":
        return "childrens_home_mode.records"
    return "admin.dashboard"


def _render_reset_failure(email: Optional[str]):
    """Return the generic reset-password failure response for HTML or JSON."""
    if request.is_json:
        return jsonify({"error": RESET_PASSWORD_GENERIC_ERROR}), 400
    return render_template(
        "auth/reset_password.html",
        error=RESET_PASSWORD_GENERIC_ERROR,
    ), 400


def _latest_password_reset_otp(user_id: int) -> Optional[OTPEvent]:
    """Return the latest password reset OTP event for a user."""
    return (
        OTPEvent.query.filter_by(user_id=user_id, action_context="password_reset")
        .order_by(OTPEvent.id.desc())
        .first()
    )


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user with lockout, timing, and portal-binding controls."""
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for(_landing_endpoint_for_user(current_user)))
        return render_template("auth/login.html")

    payload = _request_payload()
    email = _normalize_email(payload.get("email"))
    raw_password = payload.get("password")
    password = raw_password if isinstance(raw_password, str) else ""
    portal = _get_payload_value(payload, "portal") or "school"
    portal_valid = portal in VALID_PORTALS

    user = User.query.filter(func.lower(User.email) == email).first() if email else None
    identifier = _audit_identifier(email, user)

    if _login_lockout_state(identifier, user, request.remote_addr):
        check_password_hash(DUMMY_PASSWORD_HASH, password)
        # Only `login_blocked` here, never `login_failed`: the real password is not
        # checked, so a blocked attempt is not a credential failure and must not
        # extend the lockout. It expires a fixed window after the last real failure.
        log_action(
            user_id=user.id if user is not None else None,
            action="login_blocked",
            target_record_type="user" if user is not None else None,
            target_record_id=user.id if user is not None else None,
            details="Login attempt blocked by lockout policy",
            attempted_identifier=identifier,
        )
        return _login_failure_response()

    if user is None:
        check_password_hash(DUMMY_PASSWORD_HASH, password)
        _log_login_failure(identifier, None, "Failed login attempt for unknown account")
        return _login_failure_response()

    password_valid = check_password_hash(user.password_hash, password)
    if not password_valid:
        _log_login_failure(identifier, user, "Failed login attempt with invalid password")
        return _login_failure_response()

    # From here on the password is correct. The denials below are audited under
    # their own actions but deliberately do NOT write `login_failed`, so they never
    # count toward lockout: they are not guessing attempts.
    if not user.is_active:
        log_action(
            user_id=user.id,
            action="login_denied_inactive",
            target_record_type="user",
            target_record_id=user.id,
            details="Login denied because the account is inactive",
            attempted_identifier=identifier,
        )
        return _login_denied_response(INACTIVE_ACCOUNT_ERROR)

    role_name = getattr(getattr(user, "role", None), "name", None)
    institution_mode = getattr(getattr(user, "role", None), "institution_mode", None)
    if role_name == "parent_guardian":
        log_action(
            user_id=user.id,
            action="login_portal_mismatch",
            target_record_type="user",
            target_record_id=user.id,
            details="Login denied because a parent account used the staff sign-in",
            attempted_identifier=identifier,
        )
        return _login_denied_response(PARENT_ACCOUNT_ERROR)

    portal_matches = portal_valid and (
        role_name == "administrator" or institution_mode == portal
    )
    if not portal_matches:
        log_action(
            user_id=user.id,
            action="login_portal_mismatch",
            target_record_type="user",
            target_record_id=user.id,
            details="Login denied because the selected portal did not match the account",
            attempted_identifier=identifier,
        )
        return _login_denied_response(PORTAL_MISMATCH_ERROR)

    login_user(user)
    session[ACTIVE_PORTAL_SESSION_KEY] = portal
    log_action(
        user_id=user.id,
        action="login",
        target_record_type="user",
        target_record_id=user.id,
        details="Successful login",
    )

    return redirect(url_for(_landing_endpoint_for_user(user)))


@auth_bp.route("/logout")
def logout():
    """Terminate the current login session and return to login."""
    logout_user()
    session.pop(ACTIVE_PORTAL_SESSION_KEY, None)
    return redirect(url_for("auth.login"))


@auth_bp.route("/switch-portal", methods=["POST"])
@login_required
@require_role("administrator")
def switch_portal():
    """Let an administrator change which portal's pages they see, without signing out.

    Display only: access rules are unchanged. Other roles are bound to their own mode,
    so only administrators can switch. Every switch is audited.
    """
    payload = _request_payload()
    portal = _get_payload_value(payload, "portal")
    if portal not in VALID_PORTALS:
        # The raw value is not logged: it is user input and may contain anything.
        log_action(
            user_id=current_user.id,
            action="portal_switch_rejected",
            target_record_type="user",
            target_record_id=current_user.id,
            details="Rejected a portal switch to an invalid portal",
        )
        if request.is_json:
            return jsonify({"error": "Choose a valid portal."}), 400
        flash("Choose a valid portal.", "error")
        return redirect(url_for("admin.dashboard"))

    previous_portal = session.get(ACTIVE_PORTAL_SESSION_KEY)
    session[ACTIVE_PORTAL_SESSION_KEY] = portal
    log_action(
        user_id=current_user.id,
        action="portal_switch",
        target_record_type="user",
        target_record_id=current_user.id,
        details=f"Switched portal from {previous_portal or 'none'} to {portal}",
    )
    if request.is_json:
        return jsonify({"message": "Portal switched.", "portal": portal})
    return redirect(url_for("admin.dashboard"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request an SMS password reset code without revealing account existence."""
    if request.method == "GET":
        return render_template("auth/forgot_password.html")

    start_time = time.monotonic()

    payload = _request_payload()
    email = _normalize_email(payload.get("email"))
    user = (
        User.query.filter(func.lower(User.email) == email).first()
        if _is_valid_email(email)
        else None
    )

    if user is not None:
        try:
            generate_otp(user, "password_reset")
            log_action(
                user_id=user.id,
                action="password_reset_requested",
                target_record_type="user",
                target_record_id=user.id,
                details="Password reset requested.",
            )
        except Exception:
            log_action(
                user_id=user.id,
                action="password_reset_otp_generation_failed",
                target_record_type="user",
                target_record_id=user.id,
                details="Password reset OTP generation failed.",
            )
    else:
        log_action(
            action="password_reset_requested_unknown_identifier",
            details="Password reset requested for unknown identifier.",
            attempted_identifier=_audit_identifier(email, None),
        )

    elapsed = time.monotonic() - start_time
    if elapsed < MIN_RESPONSE_SECONDS:
        time.sleep(MIN_RESPONSE_SECONDS - elapsed)

    if request.is_json:
        return jsonify({"message": FORGOT_PASSWORD_GENERIC_MESSAGE}), 200

    return render_template(
        "auth/forgot_password.html",
        message=FORGOT_PASSWORD_GENERIC_MESSAGE,
    )


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Verify a password reset OTP and set a new password."""
    if request.method == "GET":
        return render_template("auth/reset_password.html", email=request.args.get("email", ""))

    start_time = time.monotonic()

    payload = _request_payload()
    email = _normalize_email(payload.get("email"))
    otp_code = _get_payload_value(payload, "otp_code")
    new_password = _get_payload_value(payload, "new_password")
    user = (
        User.query.filter(func.lower(User.email) == email).first()
        if _is_valid_email(email)
        else None
    )

    otp_event = _latest_password_reset_otp(user.id) if user is not None else None
    reset_failed = (
        user is None
        or otp_event is None
        or otp_event.user_id != user.id
        or otp_event.is_verified
        or not _is_valid_password(new_password)
        or not otp_code
        or not verify_otp(otp_event, otp_code)
    )

    if reset_failed:
        log_action(
            user_id=user.id if user is not None else None,
            action="password_reset_failed",
            target_record_type="user" if user is not None else None,
            target_record_id=user.id if user is not None else None,
            details="Password reset failed.",
            attempted_identifier=_audit_identifier(email, None) if user is None else None,
        )
    else:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        log_action(
            user_id=user.id,
            action="password_reset_completed",
            target_record_type="user",
            target_record_id=user.id,
            details="Password reset completed.",
        )

    elapsed = time.monotonic() - start_time
    if elapsed < MIN_RESPONSE_SECONDS:
        time.sleep(MIN_RESPONSE_SECONDS - elapsed)

    if reset_failed:
        return _render_reset_failure(email)

    if request.is_json:
        return jsonify({"message": "Password reset successful."}), 200

    flash("Password reset successful. Sign in with your new password.", "success")
    return redirect(url_for("auth.login"))
