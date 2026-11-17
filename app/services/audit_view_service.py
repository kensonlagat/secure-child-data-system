"""Read-only audit log viewer (#31).

This module only ever reads audit_log_entries. It has no write path: the viewer's own audit
row goes through log_action() (via the bounded writer in rbac.py) like every other row.

Filters are validated against allowlists: action and record type must be values that already
exist in the log, user ids must belong to a real account, dates must be ISO dates. Anything
else is refused with SearchError, so a crafted query string cannot reach the database as a
free-text match.

Identifiers: pre-authentication rows carry `attempted_identifier`. Since #38 an unknown
identifier is stored as a keyed hash (`unknown:<40 hex>`). The viewer shows only shapes it
knows are safe; anything else (for example a raw value written before #38) is shown as its
keyed hash, computed here, never as stored text. A known account's identifier is its email,
which the user column already names, so it is not repeated.
"""

import re
from datetime import date, datetime, time, timedelta

from sqlalchemy import func

from app import db
from app.models.audit_log import AuditLogEntry
from app.models.user import User
from app.services.key_derivation import keyed_hash

PER_PAGE_OPTIONS = (25, 50, 100)
DEFAULT_PER_PAGE = 50
SYNTHETIC_CHOICES = ("exclude", "include", "only")
FILTER_NAMES = ("user_id", "action", "target_record_type", "target_record_id", "date_from", "date_to",
                "synthetic")

SAFE_IDENTIFIER = re.compile(r"^(unknown:[0-9a-f]{40}|anonymous|system:[a-z_]{1,40}|cli:[a-z-]{1,60})$")


class SearchError(ValueError):
    pass


def known_actions():
    return [row[0] for row in db.session.query(AuditLogEntry.action).distinct().order_by(AuditLogEntry.action)]


def known_record_types():
    return [row[0] for row in db.session.query(AuditLogEntry.target_record_type)
            .filter(AuditLogEntry.target_record_type.isnot(None)).distinct()
            .order_by(AuditLogEntry.target_record_type)]


def _positive_int(raw, label):
    if not re.fullmatch(r"[0-9]{1,9}", raw):
        raise SearchError(f"{label} must be a whole number.")
    value = int(raw)
    if value < 1:
        raise SearchError(f"{label} must be a whole number.")
    return value


def _iso_date(raw, label):
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", raw):
        raise SearchError(f"{label} must be a date (YYYY-MM-DD).")
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise SearchError(f"{label} must be a date (YYYY-MM-DD).") from None


def parse_filters(args):
    """Return a dict of validated filters. Unknown parameters are ignored; bad values refuse."""
    raw = {name: (args.get(name) or "").strip() for name in FILTER_NAMES}
    filters = {}
    if raw["user_id"]:
        user_id = _positive_int(raw["user_id"], "User")
        if db.session.get(User, user_id) is None:
            raise SearchError("Choose a user from the list.")
        filters["user_id"] = user_id
    if raw["action"]:
        if raw["action"] not in known_actions():
            raise SearchError("Choose an action from the list.")
        filters["action"] = raw["action"]
    if raw["target_record_type"]:
        if raw["target_record_type"] not in known_record_types():
            raise SearchError("Choose a record type from the list.")
        filters["target_record_type"] = raw["target_record_type"]
    if raw["target_record_id"]:
        filters["target_record_id"] = _positive_int(raw["target_record_id"], "Record number")
    if raw["date_from"]:
        filters["date_from"] = _iso_date(raw["date_from"], "From date")
    if raw["date_to"]:
        filters["date_to"] = _iso_date(raw["date_to"], "To date")
    if "date_from" in filters and "date_to" in filters and filters["date_from"] > filters["date_to"]:
        raise SearchError("The from date must be on or before the to date.")
    if raw["synthetic"] and raw["synthetic"] not in SYNTHETIC_CHOICES:
        raise SearchError("Choose whether to show synthetic rows from the list.")
    if raw["synthetic"] and raw["synthetic"] != "exclude":
        filters["synthetic"] = raw["synthetic"]
    return filters


def parse_paging(args):
    try:
        page = max(1, min(int(args.get("page", 1)), 100000))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(args.get("per_page", DEFAULT_PER_PAGE))
    except (TypeError, ValueError):
        per_page = DEFAULT_PER_PAGE
    if per_page not in PER_PAGE_OPTIONS:
        per_page = DEFAULT_PER_PAGE
    return page, per_page


def _apply(query, filters):
    if "user_id" in filters:
        query = query.filter(AuditLogEntry.user_id == filters["user_id"])
    if "action" in filters:
        query = query.filter(AuditLogEntry.action == filters["action"])
    if "target_record_type" in filters:
        query = query.filter(AuditLogEntry.target_record_type == filters["target_record_type"])
    if "target_record_id" in filters:
        query = query.filter(AuditLogEntry.target_record_id == filters["target_record_id"])
    if "date_from" in filters:
        query = query.filter(AuditLogEntry.timestamp >= datetime.combine(filters["date_from"], time.min))
    if "date_to" in filters:
        query = query.filter(AuditLogEntry.timestamp < datetime.combine(filters["date_to"] + timedelta(days=1),
                                                                        time.min))
    synthetic = filters.get("synthetic", "exclude")
    if synthetic == "exclude":
        query = query.filter(AuditLogEntry.is_synthetic.is_(False))
    elif synthetic == "only":
        query = query.filter(AuditLogEntry.is_synthetic.is_(True))
    return query


def display_identifier(entry):
    """The identifier as the viewer may show it: a known safe shape, or a keyed hash."""
    value = entry.attempted_identifier
    if value is None:
        return None
    if SAFE_IDENTIFIER.fullmatch(value):
        return value
    if entry.user_id is not None:
        return None  # a known account's email; the user column already names the account
    return f"unknown:{keyed_hash('audit-identifier', value)[:40]}"


def search(filters, page, per_page):
    """Return (rows, total). Each row is a plain dict of display-safe values."""
    query = _apply(db.session.query(AuditLogEntry), filters)
    total = query.with_entities(func.count(AuditLogEntry.id)).scalar() or 0
    entries = (query.order_by(AuditLogEntry.timestamp.desc(), AuditLogEntry.id.desc())
               .offset((page - 1) * per_page).limit(per_page).all())
    user_ids = {entry.user_id for entry in entries if entry.user_id is not None}
    users = {user.id: user for user in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    rows = []
    for entry in entries:
        user = users.get(entry.user_id)
        rows.append({
            "id": entry.id,
            "timestamp": entry.timestamp,
            "user": user.full_name if user else None,
            "user_role": user.role.name if user and user.role else None,
            "identifier": display_identifier(entry),
            "action": entry.action,
            "target_record_type": entry.target_record_type,
            "target_record_id": entry.target_record_id,
            "details": entry.details,
            "ip_address": entry.ip_address,
            "is_synthetic": entry.is_synthetic,
        })
    return rows, total
