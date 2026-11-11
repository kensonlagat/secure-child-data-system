"""Administrator user management (#30).

Rules enforced on the server (the UI only mirrors them):
- New staff accounts get a random password nobody knows. The person receives an SMS
  set-password code (a standard password_reset OTP, completed on /reset-password), so
  administrators never know anyone's password.
- Any path that ends in an active administrator account (creating one, reactivating one)
  needs an OTP sent to the acting administrator, bound to that account (grant_admin).
- Administrators cannot edit, deactivate or reactivate their own account, and the last
  active administrator cannot be deactivated.
- Role and phone number of an administrator account cannot be changed here (a phone
  change would redirect that administrator's reset codes).
- Changing any other account's phone number needs an OTP sent to the acting administrator,
  bound to the target account and to the new number (change_phone). Otherwise someone
  holding only an admin session could point a safeguarding lead's phone at their own,
  use Forgot password, and receive the reset code.
- Every change is audited, with field names only, never values such as phone numbers.
"""

import re
import secrets

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash

from app import db
from app.blueprints.admin.routes import admin_bp
from app.blueprints.auth.routes import EMAIL_REGEX
from app.middleware.rbac import require_role
from app.models.otp_event import OTPEvent
from app.models.user import Role, User
from app.services.audit_service import log_action
from app.services.key_derivation import keyed_hash
from app.services.otp_service import generate_otp, verify_otp

E164_PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
GRANT_ADMIN_CONTEXT = "grant_admin"
CHANGE_PHONE_CONTEXT_PREFIX = "change_phone:"
ACCOUNT_SETUP_CONTEXT = "password_reset"  # completed on the existing reset page
NON_STAFF_ROLES = {"parent_guardian"}  # parents get their own sign-in later (#67)


def _audit(action, target_user_id, details):
    log_action(
        user_id=current_user.id,
        action=action,
        target_record_type="user",
        target_record_id=target_user_id,
        details=details,
    )


def _get_user_or_404(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    return user


def _refuse_self(user, attempted):
    """Refuse (403) and audit any attempt to manage the administrator's own account."""
    if user.id == current_user.id:
        _audit("user_change_denied_self", user.id, f"Refused: cannot {attempted} your own account")
        abort(403)


def _is_admin(user):
    return getattr(user.role, "name", None) == "administrator"


def _active_admin_count():
    return (
        User.query.join(Role)
        .filter(Role.name == "administrator", User.is_active.is_(True))
        .count()
    )


def _staff_roles():
    return Role.query.filter(Role.name.notin_(NON_STAFF_ROLES)).order_by(Role.name).all()


def _send_account_setup_code(user):
    """Send the set-password code. Returns True when the SMS went out."""
    try:
        generate_otp(user, ACCOUNT_SETUP_CONTEXT)
    except Exception:
        _audit("account_setup_code_send_failed", user.id, "Could not send the set-password code")
        return False
    _audit("account_setup_code_sent", user.id, "Set-password code sent to the account's phone")
    return True


def _start_admin_grant(user):
    """Send the acting administrator an OTP that would activate this administrator account."""
    try:
        generate_otp(current_user, GRANT_ADMIN_CONTEXT, target_record_id=user.id)
    except Exception:
        _audit("admin_grant_otp_send_failed", user.id, "Could not send the OTP to activate an administrator")
        flash("The verification code could not be sent, so the administrator account stays inactive.", "error")
        return redirect(url_for("admin.list_users"))
    _audit("admin_grant_requested", user.id, "OTP sent to activate an administrator account")
    return redirect(url_for("admin.grant_admin", user_id=user.id))


def _change_phone_context(new_phone):
    """OTP context for changing a phone number, bound to the new number.

    A code issued for one number can't then be used to set a different one. The number is
    stored only as a keyed hash: a plain hash of a phone number can be reversed by trying
    every number, and OTP rows must not hold phone numbers.
    """
    digest = keyed_hash("change-phone-context", new_phone)  # subkey, not SECRET_KEY (#73)
    return CHANGE_PHONE_CONTEXT_PREFIX + digest[:32]


def _render_user_form(user, *, values, errors, otp_pending=False):
    return render_template(
        "admin/users/form.html", roles=_staff_roles(), user=user, values=values, errors=errors,
        otp_pending=otp_pending,
    )


def _start_phone_change(user, context):
    """Send the acting administrator an OTP for this phone change. Nothing is saved yet."""
    try:
        generate_otp(current_user, context, target_record_id=user.id)
    except Exception:
        _audit("phone_change_otp_send_failed", user.id, "Could not send the OTP to change a phone number")
        return _render_user_form(
            user, values=request.form,
            errors={"phone_number": "The verification code could not be sent, so nothing was saved."},
        ), 503
    _audit("phone_change_requested", user.id, "OTP sent to the acting administrator to change a phone number")
    return _render_user_form(user, values=request.form, errors={}, otp_pending=True)


def _phone_change_verified(user, context, otp_code):
    otp_event = (
        OTPEvent.query.filter_by(user_id=current_user.id, action_context=context, target_record_id=user.id)
        .order_by(OTPEvent.id.desc())
        .first()
    )
    return (
        otp_event is not None
        and otp_event.user_id == current_user.id  # identity-bound, checked explicitly
        and otp_event.target_record_id == user.id  # bound to this account
        and isinstance(otp_code, str)
        and bool(otp_code.strip())
        and verify_otp(otp_event, otp_code.strip())  # expiry, attempts and single use
    )


def _clean(value):
    return value.strip() if isinstance(value, str) else ""


def _validate_profile(form, *, require_email):
    """Return (data, errors) for the shared profile fields."""
    data = {
        "full_name": _clean(form.get("full_name")),
        "phone_number": _clean(form.get("phone_number")),
        "assigned_class": _clean(form.get("assigned_class")) or None,
    }
    errors = {}
    if require_email:
        data["email"] = _clean(form.get("email")).lower()
        if not data["email"] or len(data["email"]) > 120 or not EMAIL_REGEX.match(data["email"]):
            errors["email"] = "Enter a valid email address."
        elif User.query.filter(db.func.lower(User.email) == data["email"]).first():
            errors["email"] = "An account with this email already exists."
    if not data["full_name"] or len(data["full_name"]) > 120:
        errors["full_name"] = "Enter the person's full name (up to 120 characters)."
    if not E164_PHONE_PATTERN.fullmatch(data["phone_number"]):
        errors["phone_number"] = "Enter the phone number in international format, e.g. +254712345678."
    if data["assigned_class"] and len(data["assigned_class"]) > 50:
        errors["assigned_class"] = "Class names are up to 50 characters."

    role = None
    role_id = form.get("role_id")
    try:
        role = db.session.get(Role, int(role_id)) if role_id else None
    except (TypeError, ValueError):
        role = None
    if role is None or role.name in NON_STAFF_ROLES:
        errors["role_id"] = "Choose a staff role."
    data["role"] = role
    if role is not None and role.name != "teacher":
        data["assigned_class"] = None  # only teachers have a class
    return data, errors


@admin_bp.route("/users")
@login_required
@require_role("administrator")
def list_users():
    """List staff accounts. The template shows the active portal's staff plus administrators
    (display only, like the rest of the portal separation)."""
    users = (
        User.query.join(Role)
        .filter(Role.name.notin_(NON_STAFF_ROLES))
        .order_by(Role.name, User.full_name)
        .all()
    )
    return render_template("admin/users/list.html", users=users)


@admin_bp.route("/users/new")
@login_required
@require_role("administrator")
def new_user_form():
    return render_template("admin/users/form.html", roles=_staff_roles(), user=None, values={}, errors={})


@admin_bp.route("/users", methods=["POST"])
@login_required
@require_role("administrator")
def create_user():
    data, errors = _validate_profile(request.form, require_email=True)
    if errors:
        return render_template(
            "admin/users/form.html", roles=_staff_roles(), user=None, values=request.form, errors=errors
        ), 400

    role = data["role"]
    user = User(
        full_name=data["full_name"],
        email=data["email"],
        phone_number=data["phone_number"],
        assigned_class=data["assigned_class"],
        # A random password nobody is told: the person sets their own with the SMS code.
        password_hash=generate_password_hash(secrets.token_urlsafe(32)),
        role_id=role.id,
        # A new administrator stays inactive until the acting admin confirms an OTP.
        is_active=role.name != "administrator",
    )
    db.session.add(user)
    db.session.commit()
    _audit("create_user", user.id, f"Created {role.name} account")

    if role.name == "administrator":
        return _start_admin_grant(user)

    if _send_account_setup_code(user):
        flash(f"Account created. {user.full_name} has been sent a code to set their password.", "success")
    else:
        flash(
            "Account created, but the set-password code could not be sent. "
            "They can use Forgot password to get a new code.",
            "warning",
        )
    return redirect(url_for("admin.list_users"))


@admin_bp.route("/users/<int:user_id>/grant-admin", methods=["GET", "POST"])
@login_required
@require_role("administrator")
def grant_admin(user_id):
    """Confirm the OTP that activates an administrator account."""
    user = _get_user_or_404(user_id)
    _refuse_self(user, "activate")
    if not _is_admin(user) or user.is_active:
        flash("There is no pending administrator activation for this account.", "info")
        return redirect(url_for("admin.list_users"))

    if request.method == "GET":
        return render_template("admin/users/grant_admin.html", user=user, error=None)

    otp_code = request.form.get("otp_code")
    otp_event = (
        OTPEvent.query.filter_by(
            user_id=current_user.id, action_context=GRANT_ADMIN_CONTEXT, target_record_id=user.id
        )
        .order_by(OTPEvent.id.desc())
        .first()
    )
    verified = (
        otp_event is not None
        and otp_event.user_id == current_user.id  # identity-bound, checked explicitly
        and isinstance(otp_code, str)
        and bool(otp_code.strip())
        and verify_otp(otp_event, otp_code.strip())  # expiry, attempts and single use
    )
    if not verified:
        _audit("admin_grant_otp_failed", user.id, "OTP verification failed while activating an administrator")
        return render_template(
            "admin/users/grant_admin.html", user=user, error="The code is not valid. Request a new one if needed."
        ), 400

    user.is_active = True
    db.session.commit()
    _audit("admin_granted", user.id, "Administrator account activated after OTP verification")
    if _send_account_setup_code(user):
        flash(f"{user.full_name} is now an administrator and has been sent a code to set their password.", "success")
    else:
        flash("Administrator activated, but the set-password code could not be sent.", "warning")
    return redirect(url_for("admin.list_users"))


@admin_bp.route("/users/<int:user_id>/grant-admin/resend", methods=["POST"])
@login_required
@require_role("administrator")
def resend_admin_grant(user_id):
    user = _get_user_or_404(user_id)
    _refuse_self(user, "activate")
    if not _is_admin(user) or user.is_active:
        return redirect(url_for("admin.list_users"))
    return _start_admin_grant(user)


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@require_role("administrator")
def edit_user(user_id):
    user = _get_user_or_404(user_id)
    _refuse_self(user, "edit")
    if request.method == "GET":
        return render_template("admin/users/form.html", roles=_staff_roles(), user=user, values={}, errors={})

    data, errors = _validate_profile(request.form, require_email=False)
    role = data["role"]
    if role is not None and not errors:
        if _is_admin(user) and role.name != "administrator":
            errors["role_id"] = "An administrator's role can't be changed here. Deactivate the account instead."
        elif not _is_admin(user) and role.name == "administrator":
            errors["role_id"] = "Create administrators with New user, which needs a verification code."
        elif _is_admin(user) and data["phone_number"] != user.phone_number:
            errors["phone_number"] = "An administrator's phone number can't be changed here."
    if errors:
        return _render_user_form(user, values=request.form, errors=errors), 400

    # A phone change saves nothing until the acting administrator confirms an OTP. The first
    # submit (no otp_code field, or "Send a new code") sends the code; the resubmit with the
    # code applies every change in the form together.
    phone_changed = data["phone_number"] != user.phone_number
    if phone_changed:
        context = _change_phone_context(data["phone_number"])
        if "otp_code" not in request.form or request.form.get("resend"):
            return _start_phone_change(user, context)
        if not _phone_change_verified(user, context, request.form.get("otp_code")):
            _audit("phone_change_otp_failed", user.id, "OTP verification failed while changing a phone number")
            return _render_user_form(
                user, values=request.form, otp_pending=True,
                errors={"otp_code": "The code is not valid. Send a new code if needed."},
            ), 400

    changed = []
    for field in ("full_name", "phone_number", "assigned_class"):
        if getattr(user, field) != data[field]:
            setattr(user, field, data[field])
            changed.append(field)
    if user.role_id != role.id:
        user.role_id = role.id
        changed.append("role")
    if not changed:
        flash("No changes to save.", "info")
        return redirect(url_for("admin.list_users"))
    # No separate commit: log_action() commits these changes together with the first audit
    # row, so a phone change is never saved without its phone_changed row.
    if phone_changed:
        _audit("phone_changed", user.id, "Phone number changed after OTP verification")
    _audit("user_updated", user.id, f"Updated fields: {', '.join(changed)}")
    flash(f"Saved changes to {user.full_name}.", "success")
    return redirect(url_for("admin.list_users"))


@admin_bp.route("/users/<int:user_id>/deactivate", methods=["POST"])
@login_required
@require_role("administrator")
def deactivate_user(user_id):
    user = _get_user_or_404(user_id)
    _refuse_self(user, "deactivate")
    if not user.is_active:
        flash("That account is already inactive.", "info")
        return redirect(url_for("admin.list_users"))
    if _is_admin(user) and _active_admin_count() <= 1:
        _audit("user_deactivation_refused", user.id, "Refused: cannot deactivate the last active administrator")
        flash("You can't deactivate the last active administrator.", "error")
        return redirect(url_for("admin.list_users"))

    user.is_active = False
    db.session.commit()
    _audit("user_deactivated", user.id, "Account deactivated; existing sessions end on their next request")
    flash(f"{user.full_name} has been deactivated and signed out.", "success")
    return redirect(url_for("admin.list_users"))


@admin_bp.route("/users/<int:user_id>/reactivate", methods=["POST"])
@login_required
@require_role("administrator")
def reactivate_user(user_id):
    user = _get_user_or_404(user_id)
    _refuse_self(user, "reactivate")
    if user.is_active:
        flash("That account is already active.", "info")
        return redirect(url_for("admin.list_users"))
    if _is_admin(user):
        return _start_admin_grant(user)  # an active administrator always needs the OTP

    user.is_active = True
    db.session.commit()
    _audit("user_reactivated", user.id, "Account reactivated")
    flash(f"{user.full_name} has been reactivated.", "success")
    return redirect(url_for("admin.list_users"))
