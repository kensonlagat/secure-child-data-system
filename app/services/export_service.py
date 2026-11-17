"""Building OTP-protected CSV exports (#65). Administrators only (decided in the routes and
access_service). Columns always come from the requester's visible-field allowlist. The CSV is
built in memory and never written to disk. Cells that a spreadsheet would run as formulas are
escaped. The file contains DECRYPTED values: whoever downloads it becomes responsible for it.
Audit rows carry counts and field names, never data."""

import csv
import hashlib
import io
import json
from datetime import datetime

from app import db
from app.models.child_record import ChildRecord
from app.models.export import EXPORT_TYPES, ExportRequest
from app.models.school_class import Enrolment
from app.services.access_service import get_accessible_records, get_visible_fields
from app.services.audit_service import log_action

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
CONTEXT_PREFIX = "bulk_export:"


class ExportError(ValueError):
    """Invalid export request. The message is safe to show."""


def params_hash(export_type, target_id, columns):
    payload = json.dumps({"type": export_type, "target": target_id, "columns": list(columns)}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def otp_context(request_row):
    """Bound to the exact export: a code issued for one request can't release another."""
    return CONTEXT_PREFIX + request_row.params_hash[:32]


def _rows(user, export_type, target_id):
    scoped = get_accessible_records(user)
    if export_type == "child_file":
        return scoped.filter(ChildRecord.id == target_id).all()
    current = Enrolment.query.with_entities(Enrolment.child_record_id).filter(
        Enrolment.class_id == target_id, Enrolment.ended_on.is_(None))
    return scoped.filter(ChildRecord.id.in_(current)).order_by(ChildRecord.id).all()


def create_request(user, export_type, target_id, columns):
    if export_type not in EXPORT_TYPES:
        raise ExportError("Choose what to export.")
    visible = get_visible_fields(user)
    columns = [c for c in dict.fromkeys(columns) if c]
    if not columns or any(c not in visible for c in columns):
        raise ExportError("Choose columns you are allowed to see.")
    if not _rows(user, export_type, target_id):
        raise ExportError("There is nothing to export for that choice.")
    row = ExportRequest(user_id=user.id, export_type=export_type, target_id=target_id, columns=",".join(columns),
                        params_hash=params_hash(export_type, target_id, columns))
    db.session.add(row)
    db.session.flush()
    log_action(user_id=user.id, action="export_requested", target_record_type="export_request",
               target_record_id=row.id, details=f"Requested {export_type} for id {target_id}: {len(columns)} column(s)")
    return row


def _safe(value):
    text = "" if value is None else (value.isoformat() if hasattr(value, "isoformat") else str(value))
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def build_csv(user, request_row):
    """Return (csv_text, row_count) built in memory from the request's fixed parameters."""
    columns = request_row.columns.split(",")
    if params_hash(request_row.export_type, request_row.target_id, columns) != request_row.params_hash:
        raise ExportError("This export request was changed and can't be used.")
    visible = set(get_visible_fields(user))
    if any(c not in visible for c in columns):
        raise ExportError("You are no longer allowed to see some of these columns.")
    rows = _rows(user, request_row.export_type, request_row.target_id)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for record in rows:
        writer.writerow([_safe(getattr(record, column)) for column in columns])
    return buffer.getvalue(), len(rows)


def complete(user, request_row, row_count):
    request_row.status, request_row.completed_at = "completed", datetime.utcnow()
    log_action(user_id=user.id, action="export_completed", target_record_type="export_request",
               target_record_id=request_row.id,
               details=(f"Exported {request_row.export_type} for id {request_row.target_id}: {row_count} row(s), "
                        f"{len(request_row.columns.split(','))} column(s): {request_row.columns}"))
