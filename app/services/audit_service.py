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
    entry.attempted_identifier = (
        attempted_identifier[:255] if attempted_identifier is not None else None
    )
    entry.action = action
    entry.target_record_type = target_record_type
    entry.target_record_id = target_record_id
    entry.details = details
    entry.ip_address = request.remote_addr if request else None

    db.session.add(entry)
    db.session.commit()
    return entry


def audit_stats(action, *, since=None, user_id=None, user_is_null=False, identifier=None, ip_address=None,
                details=None, target_type=None, target_id=None, target_is_null=False):
    """Return (count, latest timestamp) of matching audit rows, without reading any row (#19).

    Lockouts, bounded audit writes and rate limits need counts while the signed-in user (or an
    anonymous visitor) can't SELECT audit rows under row-level security. On PostgreSQL this
    calls the SECURITY DEFINER function audit_stats(), which returns only a count and a
    timestamp. Elsewhere (the SQLite test database) it runs the same filters directly.
    None means "don't filter on this"; *_is_null asks for rows where the column is NULL.
    """
    from sqlalchemy import func, text

    if db.session.get_bind().dialect.name == "postgresql":
        row = db.session.execute(
            text("SELECT row_count, latest FROM audit_stats(:action, :since, :user_id, :user_null, :identifier, "
                 ":ip, :details, :target_type, :target_id, :target_null)"),
            {"action": action, "since": since, "user_id": user_id, "user_null": user_is_null,
             "identifier": identifier, "ip": ip_address, "details": details, "target_type": target_type,
             "target_id": target_id, "target_null": target_is_null}).one()
        return int(row[0] or 0), row[1]
    query = db.session.query(func.count(AuditLogEntry.id), func.max(AuditLogEntry.timestamp)).filter(
        AuditLogEntry.action == action)
    if since is not None:
        query = query.filter(AuditLogEntry.timestamp > since)
    if user_id is not None:
        query = query.filter(AuditLogEntry.user_id == user_id)
    if user_is_null:
        query = query.filter(AuditLogEntry.user_id.is_(None))
    if identifier is not None:
        query = query.filter(AuditLogEntry.attempted_identifier == identifier)
    if ip_address is not None:
        query = query.filter(AuditLogEntry.ip_address == ip_address)
    if details is not None:
        query = query.filter(AuditLogEntry.details == details)
    if target_type is not None:
        query = query.filter(AuditLogEntry.target_record_type == target_type)
    if target_id is not None:
        query = query.filter(AuditLogEntry.target_record_id == target_id)
    if target_is_null:
        query = query.filter(AuditLogEntry.target_record_id.is_(None))
    count, latest = query.one()
    return int(count or 0), latest
