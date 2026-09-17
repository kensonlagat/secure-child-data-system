"""Read-only feature extraction for anomaly detection.

This module has no side effects: it never writes to the database and it does
not train or score any model. It only converts historical AuditLogEntry rows
into numeric feature vectors suitable for downstream anomaly detection.

All "last hour" windows are computed relative to each entry's own timestamp,
not the current wall-clock time. That makes the features correct for historical
backfills and training datasets.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
from sqlalchemy import func, distinct

from app.models.audit_log import AuditLogEntry
from app.models.user import Role, User

FAILED_AUTH_ACTIONS = {
    "login_failed",
    "legal_status_change_otp_failed",
    "legal_status_change_approval_otp_failed",
}
SECONDS_SINCE_NO_PREVIOUS_ACTION = 86400
FEATURE_COLUMNS = [
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "actions_last_hour",
    "denied_actions_last_hour",
    "failed_auth_last_hour",
    "distinct_records_last_hour",
    "seconds_since_last_action",
]


def _last_hour_window(timestamp):
    """Return the inclusive one-hour lookback window for a timestamp."""
    start_time = timestamp - timedelta(hours=1)
    return start_time, timestamp


def extract_features_for_entry(entry, session):
    """Extract numeric features for one audit-log entry.

    The returned dictionary is suitable for later conversion into a pandas
    DataFrame or direct use by anomaly-detection models.
    """
    timestamp = entry.timestamp
    if timestamp is None:
        return {column: 0 for column in FEATURE_COLUMNS}

    window_start, window_end = _last_hour_window(timestamp)

    same_user_window = (
        session.query(AuditLogEntry)
        .filter(
            AuditLogEntry.user_id == entry.user_id,
            AuditLogEntry.timestamp > window_start,
            AuditLogEntry.timestamp <= window_end,
        )
    )

    actions_last_hour = same_user_window.count()
    denied_actions_last_hour = same_user_window.filter(
        AuditLogEntry.action == "access_denied"
    ).count()
    failed_auth_last_hour = same_user_window.filter(
        AuditLogEntry.action.in_(FAILED_AUTH_ACTIONS)
    ).count()
    distinct_records_last_hour = (
        session.query(func.count(distinct(AuditLogEntry.target_record_id)))
        .filter(
            AuditLogEntry.user_id == entry.user_id,
            AuditLogEntry.timestamp > window_start,
            AuditLogEntry.timestamp <= window_end,
            AuditLogEntry.target_record_id.isnot(None),
        )
        .scalar()
        or 0
    )

    previous_entry_timestamp = (
        session.query(func.max(AuditLogEntry.timestamp))
        .filter(
            AuditLogEntry.user_id == entry.user_id,
            AuditLogEntry.timestamp < timestamp,
        )
        .scalar()
    )
    if previous_entry_timestamp is None:
        seconds_since_last_action = SECONDS_SINCE_NO_PREVIOUS_ACTION
    else:
        seconds_since_last_action = int((timestamp - previous_entry_timestamp).total_seconds())

    return {
        "hour_of_day": timestamp.hour,
        "day_of_week": timestamp.weekday(),
        "is_weekend": int(timestamp.weekday() >= 5),
        "actions_last_hour": int(actions_last_hour),
        "denied_actions_last_hour": int(denied_actions_last_hour),
        "failed_auth_last_hour": int(failed_auth_last_hour),
        "distinct_records_last_hour": int(distinct_records_last_hour),
        "seconds_since_last_action": int(seconds_since_last_action),
    }


def extract_training_dataset(role_name, session):
    """Build a pandas DataFrame of features for all audit rows in one role.

    The query is read-only and filters AuditLogEntry rows through User -> Role
    so the resulting dataset matches the selected role's activity history.
    """
    entries = (
        session.query(AuditLogEntry)
        .join(User, AuditLogEntry.user_id == User.id)
        .join(Role, User.role_id == Role.id)
        .filter(Role.name == role_name)
        .order_by(AuditLogEntry.timestamp.asc(), AuditLogEntry.id.asc())
        .all()
    )

    feature_rows = [extract_features_for_entry(entry, session) for entry in entries]
    return pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
