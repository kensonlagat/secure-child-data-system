"""Scoped search and pagination for the record lists (#32).

Rules:
- Every search starts from access_service.get_accessible_records() and only narrows it.
- A role may filter only on fields it can see. A filter on any other field is refused
  (SearchError, a 400 with no data), so a hidden value can't be inferred by filtering.
- The name term never goes in a URL: it is POSTed, kept in the session per mode, and
  dropped on clear, sign-in and sign-out. URLs carry only page, per_page and
  non-sensitive filters.
- Names are encrypted, so name matching happens in Python over the scoped set.
"""

from datetime import date

from flask import session

from app.models.child_record import ChildRecord
from app.models.legal_status_change_request import VALID_LEGAL_STATUSES
from app.models.school_class import Enrolment

SEARCH_SESSION_KEY = "record_search"
PER_PAGE_OPTIONS = (10, 25, 50)
DEFAULT_PER_PAGE = 25
NAME_TERM_MAX_LENGTH = 100

# filter name -> (visible field it requires, modes it applies to)
FILTER_RULES = {
    "class_id": ("class_label", {"school"}),
    "dob_from": ("date_of_birth", {"school", "childrens_home"}),
    "dob_to": ("date_of_birth", {"school", "childrens_home"}),
    "legal_status": ("legal_status", {"childrens_home"}),
}
NAME_FIELD = "full_name"


class SearchError(ValueError):
    """A search the role may not run, or malformed input. The message is safe to show."""


# --- The name term (session only) ------------------------------------------------------


def get_name_term(mode):
    return (session.get(SEARCH_SESSION_KEY) or {}).get(mode)


def set_name_term(mode, term, visible_fields):
    term = (term or "").strip()
    if term and NAME_FIELD not in visible_fields:
        raise SearchError("Your role cannot search by name.")
    if len(term) > NAME_TERM_MAX_LENGTH:
        raise SearchError(f"Search for at most {NAME_TERM_MAX_LENGTH} characters.")
    terms = dict(session.get(SEARCH_SESSION_KEY) or {})
    if term:
        terms[mode] = term
    else:
        terms.pop(mode, None)
    session[SEARCH_SESSION_KEY] = terms


def clear_name_term(mode=None):
    if mode is None:
        session.pop(SEARCH_SESSION_KEY, None)
        return
    terms = dict(session.get(SEARCH_SESSION_KEY) or {})
    terms.pop(mode, None)
    session[SEARCH_SESSION_KEY] = terms


# --- Query-string filters and paging ------------------------------------------------------


def _positive_int(value, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number >= 1 else default


def parse_paging(args):
    per_page = _positive_int(args.get("per_page"), DEFAULT_PER_PAGE)
    if per_page not in PER_PAGE_OPTIONS:
        per_page = DEFAULT_PER_PAGE
    return _positive_int(args.get("page"), 1), per_page


def parse_filters(args, visible_fields, mode):
    """Return the validated non-sensitive filters, or raise SearchError."""
    filters = {}
    for name in args:
        if name in ("page", "per_page"):
            continue
        if name not in FILTER_RULES:
            raise SearchError(f"Unknown filter: {name}.")
        required_field, modes = FILTER_RULES[name]
        if mode not in modes or required_field not in visible_fields:
            raise SearchError("Your role cannot filter by that field.")
        raw = (args.get(name) or "").strip()
        if not raw:
            continue
        if name == "class_id":
            if not raw.isdigit():
                raise SearchError("class_id must be a number.")
            filters[name] = int(raw)
        elif name in ("dob_from", "dob_to"):
            try:
                filters[name] = date.fromisoformat(raw)
            except ValueError as error:
                raise SearchError(f"{name} must be a date (YYYY-MM-DD).") from error
        elif name == "legal_status":
            if raw not in VALID_LEGAL_STATUSES:
                raise SearchError("Unknown legal status.")
            filters[name] = raw
    return filters


def apply_filters(query, filters):
    if "class_id" in filters:
        current = Enrolment.query.with_entities(Enrolment.child_record_id).filter(
            Enrolment.ended_on.is_(None), Enrolment.class_id == filters["class_id"])
        query = query.filter(ChildRecord.id.in_(current))
    if "dob_from" in filters:
        query = query.filter(ChildRecord.date_of_birth >= filters["dob_from"])
    if "dob_to" in filters:
        query = query.filter(ChildRecord.date_of_birth <= filters["dob_to"])
    if "legal_status" in filters:
        query = query.filter(ChildRecord.legal_status == filters["legal_status"])
    return query


def paginate(query, name_term, page, per_page):
    """Return (records, total). A page past the end is empty but still reports the total.
    Without a name term, paging runs in SQL; with one, the scoped set is decrypted and
    matched case-insensitively in Python."""
    query = query.order_by(ChildRecord.id)
    start = (page - 1) * per_page
    if name_term:
        needle = name_term.casefold()
        matches = [r for r in query.all() if r.full_name and needle in r.full_name.casefold()]
        return matches[start: start + per_page], len(matches)
    total = query.order_by(None).count()
    return query.offset(start).limit(per_page).all(), total
