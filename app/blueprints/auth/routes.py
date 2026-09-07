"""
Authentication Module (Sprint 1).

Scope per proposal:
- User registration (by admin, with role assignment)
- Secure login with password hashing
- OTP verification for sensitive actions (delivered via Africa's Talking)

This is a stub — real logic goes here in Sprint 1. Kept minimal now so the
app can boot and the blueprint registration in app/__init__.py doesn't fail.
"""
from flask import Blueprint, render_template

auth_bp = Blueprint("auth", __name__, template_folder="../../templates")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    # TODO (Sprint 1): validate credentials, check_password_hash,
    # flask_login.login_user(), then redirect based on role/institution mode.
    return "Login page placeholder"


@auth_bp.route("/logout")
def logout():
    # TODO (Sprint 1): flask_login.logout_user()
    return "Logout placeholder"
