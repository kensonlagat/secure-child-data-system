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
    user_id: int,
    action: str,
    target_record_type: Optional[str] = None,
    target_record_id: Optional[int] = None,
    details: Optional[str] = None,
):
    """Create and persist a single append-only audit log entry."""
    entry = AuditLogEntry()
    entry.user_id = user_id
    entry.action = action
    entry.target_record_type = target_record_type
    entry.target_record_id = target_record_id
    entry.details = details
    entry.ip_address = request.remote_addr if request else None

    db.session.add(entry)
    db.session.commit()
    return entry
