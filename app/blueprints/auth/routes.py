"""Authentication routes for Sprint 1 registration and login."""
import re
from typing import Optional

from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.middleware.rbac import require_role
from app.models.user import Role, User
from app.services.audit_service import log_action

auth_bp = Blueprint("auth", __name__, template_folder="../../templates")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8


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

    institution_mode = user.role.institution_mode if user.role else None
    if institution_mode == "school":
        return redirect(url_for("school_mode.records"))
    if institution_mode == "childrens_home":
        return redirect(url_for("childrens_home_mode.records"))
    return redirect(url_for("admin.dashboard"))


@auth_bp.route("/logout")
def logout():
    """Terminate the current login session and return to login."""
    logout_user()
    return redirect(url_for("auth.login"))
