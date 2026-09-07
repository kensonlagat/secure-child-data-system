"""
Single entry point for writing audit log entries. Route handlers and
services should call log_action() rather than constructing AuditLogEntry
directly, so there is exactly one code path to review/test for correctness.
"""
from flask import request
from app import db
from app.models.audit_log import AuditLogEntry


def log_action(user_id: int, action: str, target_record_type: str = None,
                target_record_id: int = None, details: str = None):
    entry = AuditLogEntry(
        user_id=user_id,
        action=action,
        target_record_type=target_record_type,
        target_record_id=target_record_id,
        details=details,
        ip_address=request.remote_addr if request else None,
    )
    db.session.add(entry)
    db.session.commit()
    return entry
