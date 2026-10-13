"""
Single entry point for writing audit log entries. Route handlers and
services should call log_action() rather than constructing AuditLogEntry
directly, so there is exactly one code path to review/test for correctness.
"""
from typing import Optional

from flask import request
from app import db
from app.models.audit_log import AuditLogEntry


def log_action(
    action: str,
    user_id: Optional[int] = None,
    target_record_type: Optional[str] = None,
    target_record_id: Optional[int] = None,
    details: Optional[str] = None,
    attempted_identifier: Optional[str] = None,
):
    """Create and persist a single append-only audit log entry."""
    # `attempted_identifier` exists for pre-authentication events only, such as
    # unknown login or password-reset attempts where no real user account can be
    # attached yet. Every other caller should continue passing a real user_id.
    if user_id is None and attempted_identifier is None:
        raise ValueError("user_id is required unless attempted_identifier is provided.")

    entry = AuditLogEntry()
    entry.user_id = user_id
    entry.attempted_identifier = attempted_identifier
    entry.action = action
    entry.target_record_type = target_record_type
    entry.target_record_id = target_record_id
    entry.details = details
    entry.ip_address = request.remote_addr if request else None

    db.session.add(entry)
    db.session.commit()
    return entry
