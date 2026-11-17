"""Parent sign-in by phone and one-time code, and guardian links (#67).

No enumeration (hard rule 7): every code request gets the same answer, and every verification
failure the same message; routes add a 2-second response floor. Codes are sent only for an
active parent account with at least one active link. Unknown numbers do the same hashing work
and send nothing.

Phone numbers never appear in audit details. Audit rows carry a keyed hash of the number
(`audit-identifier` subkey, #73) as their identifier, which the rate limits and lockout count.
"""

import re
import secrets
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.models.child_record import ChildRecord
from app.models.guardian_link import IDENTITY_DOCUMENT_TYPES, RELATIONSHIPS, GuardianLink
from app.models.otp_event import OTPEvent
from app.models.user import Role, User
from app.services.audit_service import audit_stats, log_action
from app.services.key_derivation import keyed_hash
from app.services.otp_service import generate_otp, verify_otp

PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
PARENT_LOGIN_CONTEXT = "parent_login"
LINK_VERIFY_CONTEXT = "guardian_link_verify"
SENDS_PER_NUMBER_PER_HOUR = 3
SENDS_PER_IP_PER_HOUR = 20
RATE_WINDOW = timedelta(hours=1)
DUMMY_HASH = generate_password_hash("unusable-parent-code")


class LinkError(ValueError):
    """Invalid link input. The message is safe to show."""


def normalise_phone(raw):
    if not isinstance(raw, str):
        return None
    value = re.sub(r"[\s\-()]", "", raw.strip())
    return value if PHONE_PATTERN.fullmatch(value) else None


def phone_identifier(raw):
    """Keyed hash of what was typed (normalised when valid). Never the number itself."""
    value = normalise_phone(raw) or (raw if isinstance(raw, str) else "")
    return f"unknown:{keyed_hash('audit-identifier', 'phone:' + value[:40])[:40]}"


def _active_parent(phone):
    """The active parent account for this number with at least one active link, or None."""
    if phone is None:
        return None
    user = (User.query.join(Role, Role.id == User.role_id)
            .filter(User.login_phone == phone, Role.name == "parent_guardian", User.is_active.is_(True)).first())
    if user is None:
        return None
    return user if _has_active_school_link(user.id) else None


def _has_active_school_link(user_id):
    """Before sign-in the visitor is anonymous and, under row-level security (#19), can't read
    links or child records. On PostgreSQL the SECURITY DEFINER function answers yes or no."""
    from sqlalchemy import text

    if db.session.get_bind().dialect.name == "postgresql":
        return bool(db.session.execute(text("SELECT parent_has_active_link(:id)"), {"id": user_id}).scalar())
    return (GuardianLink.query.join(ChildRecord, ChildRecord.id == GuardianLink.child_record_id)
            .filter(GuardianLink.guardian_user_id == user_id, GuardianLink.status == "active",
                    ChildRecord.institution_mode == "school",  # same scope as access_service
                    ChildRecord.is_deleted.is_(False), ChildRecord.is_archived.is_(False)).first()) is not None


# --- Requesting a code ----------------------------------------------------------------------------


def _rate_limited(identifier, ip_address):
    since = datetime.utcnow() - RATE_WINDOW
    by_number, _ = audit_stats("parent_login_code_requested", identifier=identifier, since=since)
    by_ip = audit_stats("parent_login_code_requested", ip_address=ip_address, since=since)[0] if ip_address else 0
    return by_number >= SENDS_PER_NUMBER_PER_HOUR or by_ip >= SENDS_PER_IP_PER_HOUR


def _audit_rate_limited(identifier):
    """Bounded: one row per identifier per window, however often the cap is hit."""
    since = datetime.utcnow() - RATE_WINDOW
    if audit_stats("parent_login_rate_limited", identifier=identifier, since=since)[0] == 0:
        log_action(attempted_identifier=identifier, action="parent_login_rate_limited",
                   details="Parent code request over the hourly limit; nothing sent")


def request_code(raw_phone, ip_address):
    """Send a sign-in code if, and only if, the number belongs to an active linked parent and
    no limit is hit. Returns nothing: the caller always shows the same message."""
    identifier = phone_identifier(raw_phone)
    if _rate_limited(identifier, ip_address):
        _audit_rate_limited(identifier)
        return
    parent = _active_parent(normalise_phone(raw_phone))
    log_action(user_id=parent.id if parent else None, attempted_identifier=identifier,
               action="parent_login_code_requested", target_record_type="user" if parent else None,
               target_record_id=parent.id if parent else None, details="Parent sign-in code requested")
    if parent is None:
        generate_password_hash(secrets.token_hex(3))  # the same hashing work as a real code
        return
    try:
        generate_otp(parent, PARENT_LOGIN_CONTEXT, target_record_id=parent.id)
    except Exception as error:  # noqa: BLE001 - an SMS failure must look the same to the requester
        db.session.rollback()
        unsent = (OTPEvent.query.filter_by(user_id=parent.id, action_context=PARENT_LOGIN_CONTEXT,
                                           is_verified=False).order_by(OTPEvent.id.desc()).first())
        if unsent is not None:
            unsent.attempt_count = 5
            db.session.commit()
        log_action(user_id=parent.id, attempted_identifier=identifier, action="parent_login_code_send_failed",
                   target_record_type="user", target_record_id=parent.id,
                   details=f"Parent sign-in code could not be sent ({type(error).__name__})")


# --- Verifying a code -----------------------------------------------------------------------------


def _locked_out(identifier, parent, ip_address):
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=current_app.config["LOGIN_LOCKOUT_MINUTES"])
    cutoff = window_start
    if parent is not None:
        _, last = audit_stats("parent_login_succeeded", user_id=parent.id)
        if last:
            cutoff = max(cutoff, last)
    failures, _ = audit_stats("login_failed", identifier=identifier, since=cutoff)
    ip_failures = audit_stats("login_failed", ip_address=ip_address, since=window_start)[0] if ip_address else 0
    return (failures >= current_app.config["LOGIN_MAX_FAILURES"]
            or ip_failures >= current_app.config["LOGIN_IP_MAX_FAILURES"])


def verify_code(raw_phone, raw_code, ip_address):
    """Return the parent User when the code is right, else None (one generic failure)."""
    identifier = phone_identifier(raw_phone)
    code = raw_code.strip() if isinstance(raw_code, str) else ""
    parent = _active_parent(normalise_phone(raw_phone))
    if _locked_out(identifier, parent, ip_address):
        check_password_hash(DUMMY_HASH, code)
        log_action(user_id=parent.id if parent else None, attempted_identifier=identifier, action="login_blocked",
                   details="Parent sign-in code blocked by lockout policy")
        return None
    otp_event = None
    if parent is not None:
        otp_event = (OTPEvent.query.filter_by(user_id=parent.id, action_context=PARENT_LOGIN_CONTEXT,
                                              target_record_id=parent.id, is_verified=False)
                     .order_by(OTPEvent.id.desc()).first())
    if otp_event is not None and verify_otp(otp_event, code):
        return parent
    if otp_event is None:
        check_password_hash(DUMMY_HASH, code)  # the same hashing work as a real check
    log_action(user_id=parent.id if parent else None, attempted_identifier=identifier, action="login_failed",
               target_record_type="user" if parent else None, target_record_id=parent.id if parent else None,
               details="Failed parent sign-in code")
    return None


# --- Guardian links (administrators) --------------------------------------------------------------


def create_link(actor, record, raw_phone, full_name, relationship, document_type):
    phone = normalise_phone(raw_phone)
    name = (full_name or "").strip()
    if phone is None:
        raise LinkError("Enter the parent's phone number in international format, for example +254712345678.")
    if not 2 <= len(name) <= 120:
        raise LinkError("Enter the parent's name.")
    if relationship not in RELATIONSHIPS:
        raise LinkError("Choose a relationship from the list.")
    if document_type not in IDENTITY_DOCUMENT_TYPES:
        raise LinkError("Choose the identity document you checked.")
    if record is None or record.institution_mode != "school":
        raise LinkError("Parents can only be linked to school records.")
    parent = User.query.filter(User.login_phone == phone).first()
    if parent is not None and getattr(parent.role, "name", None) != "parent_guardian":
        raise LinkError("That number belongs to an account that isn't a parent account.")
    if parent is None:
        role = Role.query.filter_by(name="parent_guardian").first()
        if role is None:
            raise LinkError("The parent role is missing. Run flask seed-roles.")
        parent = User(full_name=name, email=None, login_phone=phone, phone_number=phone,
                      password_hash=generate_password_hash(secrets.token_urlsafe(32)),  # never usable
                      role_id=role.id, is_active=True)
        db.session.add(parent)
        db.session.flush()
    existing = GuardianLink.query.filter(GuardianLink.child_record_id == record.id,
                                         GuardianLink.guardian_user_id == parent.id,
                                         GuardianLink.status != "revoked").first()
    if existing is not None:
        raise LinkError("This parent is already linked to this child.")
    link = GuardianLink(child_record_id=record.id, guardian_user_id=parent.id, relationship=relationship,
                        identity_document_type=document_type, status="pending", created_by=actor.id,
                        created_at=datetime.utcnow())
    db.session.add(link)
    db.session.commit()
    log_action(user_id=actor.id, action="guardian_link_created", target_record_type="child_record",
               target_record_id=record.id,
               details=f"Guardian link {link.id} created as pending ({relationship}, {document_type} checked)")
    return link


def request_link_verification(actor, link):
    if link.status != "pending":
        raise LinkError("Only a pending link can be verified.")
    generate_otp(actor, LINK_VERIFY_CONTEXT, target_record_id=link.id)
    log_action(user_id=actor.id, action="guardian_link_verify_requested", target_record_type="guardian_link",
               target_record_id=link.id, details="Verification code sent to the acting administrator")


def verify_link(actor, link, raw_code):
    """Activate a pending link with the code sent to this administrator for this link."""
    if link.status != "pending":
        raise LinkError("Only a pending link can be verified.")
    otp_event = (OTPEvent.query.filter_by(user_id=actor.id, action_context=LINK_VERIFY_CONTEXT,
                                          target_record_id=link.id, is_verified=False)
                 .order_by(OTPEvent.id.desc()).first())
    code = raw_code.strip() if isinstance(raw_code, str) else ""
    if otp_event is None or not verify_otp(otp_event, code):
        log_action(user_id=actor.id, action="guardian_link_verify_failed", target_record_type="guardian_link",
                   target_record_id=link.id, details="Wrong, expired or missing verification code")
        raise LinkError("That code didn't work. Request a new code and try again.")
    now = datetime.utcnow()
    link.status, link.verified_by, link.verified_at = "active", actor.id, now
    db.session.commit()
    log_action(user_id=actor.id, action="guardian_link_verified", target_record_type="guardian_link",
               target_record_id=link.id, details=f"Guardian link {link.id} verified and active")


def revoke_link(actor, link):
    if link.status == "revoked":
        raise LinkError("This link is already revoked.")
    link.status, link.revoked_by, link.revoked_at = "revoked", actor.id, datetime.utcnow()
    db.session.commit()
    log_action(user_id=actor.id, action="guardian_link_revoked", target_record_type="guardian_link",
               target_record_id=link.id, details=f"Guardian link {link.id} revoked")


def links_for_admin(records_query):
    """All links for records the administrator can see, newest first."""
    record_ids = records_query.with_entities(ChildRecord.id)
    return (GuardianLink.query.filter(GuardianLink.child_record_id.in_(record_ids))
            .order_by(GuardianLink.created_at.desc(), GuardianLink.id.desc()).all())


def count_linked_children(parent):
    return db.session.query(func.count(GuardianLink.id)).filter(
        GuardianLink.guardian_user_id == parent.id, GuardianLink.status == "active").scalar() or 0
