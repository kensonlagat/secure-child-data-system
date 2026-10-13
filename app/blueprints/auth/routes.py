"""Authentication routes for Sprint 1 registration and login."""
import re
import time
from typing import Optional

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.middleware.rbac import require_role
from app.models.otp_event import OTPEvent
from app.models.user import Role, User
from app.services.audit_service import log_action
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


def _is_valid_email(email: Optional[str]) -> bool:
    """Return True when an email matches a basic valid format."""
    return bool(email and EMAIL_REGEX.match(email))


def _is_valid_password(password: Optional[str]) -> bool:
    """Return True when a password meets minimum length requirements."""
    return bool(password and len(password) >= MIN_PASSWORD_LENGTH)


def _get_payload_value(payload: dict, key: str) -> Optional[str]:
    """Normalize text fields from JSON/form payloads."""
    value = payload.get(key)
    if isinstance(value, str):
        return value.strip()
    return value


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


@auth_bp.route("/register", methods=["POST"])
@require_role("administrator")
def register():
    """Create a user account with role assignment, guarded by admin RBAC."""
    payload = request.get_json(silent=True) or request.form
    email = _get_payload_value(payload, "email")
    password = _get_payload_value(payload, "password")
    full_name = _get_payload_value(payload, "full_name")
    phone_number = _get_payload_value(payload, "phone_number")
    role_id = _get_payload_value(payload, "role_id")

    if not _is_valid_email(email):
        return jsonify({"error": "Invalid email format."}), 400

    if password is None or not _is_valid_password(password):
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    if not full_name or not phone_number or not role_id:
        return jsonify({"error": "full_name, phone_number and role_id are required."}), 400

    try:
        role_id = int(role_id)
    except (TypeError, ValueError):
        return jsonify({"error": "role_id must be an integer."}), 400

    role = db.session.get(Role, role_id)
    if role is None:
        return jsonify({"error": "Invalid role_id."}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "A user with this email already exists."}), 409

    user = User()
    user.full_name = full_name
    user.email = email
    user.phone_number = phone_number
    user.password_hash = generate_password_hash(password)
    user.role_id = role_id
    db.session.add(user)
    db.session.commit()

    log_action(
        user_id=current_user.id,
        action="create_user",
        target_record_type="user",
        target_record_id=user.id,
        details=f"Created user account for {user.email}",
    )
    return jsonify({"message": "User registered successfully.", "user_id": user.id}), 201


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user and route them to their institution mode dashboard."""
    if request.method == "GET":
        return render_template("auth/login.html")

    payload = request.get_json(silent=True) or request.form
    email = _get_payload_value(payload, "email")
    password = _get_payload_value(payload, "password")

    if not _is_valid_email(email):
        return render_template("auth/login.html", error="Invalid email format."), 400

    if password is None or not _is_valid_password(password):
        return render_template(
            "auth/login.html",
            error="Password must be at least 8 characters.",
        ), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        if user:
            log_action(
                user_id=user.id,
                action="login_failed",
                target_record_type="user",
                target_record_id=user.id,
                details="Failed login attempt with invalid credentials",
            )
        return render_template("auth/login.html", error="Invalid credentials."), 401

    login_user(user)
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
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request an SMS password reset code without revealing account existence."""
    if request.method == "GET":
        return render_template("auth/forgot_password.html")

    start_time = time.monotonic()

    payload = request.get_json(silent=True) or request.form
    email = _get_payload_value(payload, "email")
    user = User.query.filter_by(email=email).first() if _is_valid_email(email) else None

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
            attempted_identifier=email,
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

    payload = request.get_json(silent=True) or request.form
    email = _get_payload_value(payload, "email")
    otp_code = _get_payload_value(payload, "otp_code")
    new_password = _get_payload_value(payload, "new_password")
    user = User.query.filter_by(email=email).first() if _is_valid_email(email) else None

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
            attempted_identifier=email if user is None else None,
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
