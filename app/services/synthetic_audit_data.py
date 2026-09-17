"""Synthetic audit-log generation for anomaly-detection training.

This module is intentionally read-only with respect to application logic: it
only creates clearly synthetic AuditLogEntry rows for local training and test
data. It does not train a model, score anomalies, or modify any real audit
records.

The generated history is timestamped in the past and uses role-specific daily
patterns so it resembles real user activity. All anomalous rows are still
marked synthetic so they can be filtered or purged later.
"""

from __future__ import annotations

import random
from collections import defaultdict
from datetime import datetime, timedelta

from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.user import Role, User

ROLE_FAILED_AUTH_ACTIONS = {
    "login_failed",
    "legal_status_change_otp_failed",
    "legal_status_change_approval_otp_failed",
}


def _pick_record_ids(role_name, user, school_record_ids, home_record_ids, all_record_ids):
    """Pick sensible target record IDs for a role's activity."""
    if role_name == "teacher":
        scoped = school_record_ids
    elif role_name in {"social_worker", "legal_officer"}:
        scoped = home_record_ids
    else:
        scoped = all_record_ids

    if not scoped:
        scoped = all_record_ids
    return scoped


def _make_entry(user_id, action, timestamp, target_record_type=None, target_record_id=None, details=None):
    return AuditLogEntry(
        user_id=user_id,
        action=action,
        target_record_type=target_record_type,
        target_record_id=target_record_id,
        details=details,
        timestamp=timestamp,
        is_synthetic=True,
    )


def _weekday_workday(day_timestamp):
    return day_timestamp.weekday() < 5


def _role_normal_actions(role_name, rng, day_timestamp, user, record_ids):
    """Build one day's worth of normal activity for a role."""
    actions = []
    if not _weekday_workday(day_timestamp) and role_name != "administrator":
        return actions

    if role_name == "teacher":
        login_time = day_timestamp.replace(hour=rng.randint(7, 8), minute=rng.randint(0, 50), second=rng.randint(0, 59), microsecond=0)
        actions.append(_make_entry(user.id, "login", login_time, "user", user.id, "Synthetic teacher login"))
        view_count = rng.randint(1, 3)
        for index in range(view_count):
            view_time = login_time + timedelta(minutes=5 * (index + 1))
            record_id = rng.choice(record_ids) if record_ids else None
            actions.append(_make_entry(user.id, "view_records", view_time, "child_record", record_id, "Synthetic teacher record review"))
        if rng.random() < 0.35 and record_ids:
            update_time = login_time + timedelta(minutes=20)
            record_id = rng.choice(record_ids)
            actions.append(_make_entry(user.id, "update_record", update_time, "child_record", record_id, "Synthetic teacher record update"))

    elif role_name == "school_nurse":
        login_time = day_timestamp.replace(hour=rng.randint(7, 9), minute=rng.randint(0, 45), second=rng.randint(0, 59), microsecond=0)
        actions.append(_make_entry(user.id, "login", login_time, "user", user.id, "Synthetic school nurse login"))
        for index in range(rng.randint(1, 4)):
            record_id = rng.choice(record_ids) if record_ids else None
            action_time = login_time + timedelta(minutes=7 * (index + 1))
            actions.append(_make_entry(user.id, "view_records", action_time, "child_record", record_id, "Synthetic school nurse record review"))
        if rng.random() < 0.45 and record_ids:
            record_id = rng.choice(record_ids)
            action_time = login_time + timedelta(minutes=25)
            actions.append(_make_entry(user.id, "update_record", action_time, "child_record", record_id, "Synthetic school nurse medical note update"))

    elif role_name == "social_worker":
        login_time = day_timestamp.replace(hour=rng.randint(8, 9), minute=rng.randint(0, 50), second=rng.randint(0, 59), microsecond=0)
        actions.append(_make_entry(user.id, "login", login_time, "user", user.id, "Synthetic social worker login"))
        for index in range(rng.randint(1, 3)):
            record_id = rng.choice(record_ids) if record_ids else None
            action_time = login_time + timedelta(minutes=8 * (index + 1))
            actions.append(_make_entry(user.id, "view_records", action_time, "child_record", record_id, "Synthetic social worker caseload review"))
        if rng.random() < 0.5 and record_ids:
            record_id = rng.choice(record_ids)
            action_time = login_time + timedelta(minutes=18)
            actions.append(_make_entry(user.id, "update_record", action_time, "child_record", record_id, "Synthetic social worker note update"))

    elif role_name == "legal_officer":
        login_time = day_timestamp.replace(hour=rng.randint(8, 10), minute=rng.randint(0, 40), second=rng.randint(0, 59), microsecond=0)
        actions.append(_make_entry(user.id, "login", login_time, "user", user.id, "Synthetic legal officer login"))
        for index in range(rng.randint(1, 2)):
            record_id = rng.choice(record_ids) if record_ids else None
            action_time = login_time + timedelta(minutes=6 * (index + 1))
            actions.append(_make_entry(user.id, "view_records", action_time, "child_record", record_id, "Synthetic legal officer records review"))
        if rng.random() < 0.45 and record_ids:
            record_id = rng.choice(record_ids)
            action_time = login_time + timedelta(minutes=22)
            actions.append(_make_entry(user.id, "legal_status_change_requested", action_time, "child_record", record_id, "Synthetic legal status request"))

    elif role_name == "administrator":
        login_time = day_timestamp.replace(hour=rng.randint(7, 9), minute=rng.randint(0, 45), second=rng.randint(0, 59), microsecond=0)
        actions.append(_make_entry(user.id, "login", login_time, "user", user.id, "Synthetic administrator login"))
        for index in range(rng.randint(1, 4)):
            record_id = rng.choice(record_ids) if record_ids else None
            action_time = login_time + timedelta(minutes=4 * (index + 1))
            actions.append(_make_entry(user.id, "view_records", action_time, "child_record", record_id, "Synthetic administrator records review"))
        if rng.random() < 0.5 and record_ids:
            record_id = rng.choice(record_ids)
            action_time = login_time + timedelta(minutes=30)
            actions.append(_make_entry(user.id, "create_record", action_time, "child_record", record_id, "Synthetic administrator record creation"))

    return actions


def _role_anomalous_actions(role_name, rng, day_timestamp, user, record_ids, anomaly_count):
    """Build a small burst of clearly anomalous synthetic activity."""
    actions = []
    if anomaly_count <= 0:
        return actions

    anomaly_start = day_timestamp.replace(hour=2, minute=rng.randint(0, 45), second=rng.randint(0, 59), microsecond=0)
    actions.append(_make_entry(user.id, "login", anomaly_start, "user", user.id, f"Synthetic anomalous {role_name} login"))

    remaining = anomaly_count - 1
    burst_actions = []
    if role_name == "legal_officer":
        burst_actions = ["login_failed", "legal_status_change_otp_failed", "legal_status_change_approval_otp_failed"]
    elif role_name in {"teacher", "school_nurse", "social_worker", "administrator"}:
        burst_actions = ["access_denied", "access_denied", "view_records", "view_records", "view_records"]
    else:
        burst_actions = ["access_denied", "login_failed", "view_records"]

    for index in range(remaining):
        action = burst_actions[index % len(burst_actions)]
        action_time = anomaly_start + timedelta(seconds=15 * (index + 1))
        record_id = rng.choice(record_ids) if record_ids else None
        target_type = "child_record" if action != "login_failed" else "user"
        target_id = record_id if action != "login_failed" else user.id
        actions.append(
            _make_entry(
                user.id,
                action,
                action_time,
                target_type,
                target_id,
                f"Synthetic anomalous {role_name} activity",
            )
        )

    return actions[:anomaly_count]


def generate_synthetic_history(session, days=30):
    """Generate clearly synthetic audit history for existing users.

    The function returns a summary mapping each role to the number of normal
    and anomalous rows inserted. It never updates or deletes real audit rows.
    """
    rng = random.Random(days * 97)
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)

    users = (
        session.query(User)
        .join(Role, User.role_id == Role.id)
        .order_by(Role.id, User.id)
        .all()
    )
    school_record_ids = [record.id for record in session.query(ChildRecord.id).filter(ChildRecord.institution_mode == "school").all()]
    home_record_ids = [record.id for record in session.query(ChildRecord.id).filter(ChildRecord.institution_mode == "childrens_home").all()]
    all_record_ids = [record.id for record in session.query(ChildRecord.id).all()]

    pending_entries = []
    summary = defaultdict(lambda: {"normal": 0, "anomalous": 0})

    for user in users:
        role_name = user.role.name if user.role else "unassigned"
        role_record_ids = _pick_record_ids(role_name, user, school_record_ids, home_record_ids, all_record_ids)
        user_normal_count = 0

        for day_offset in range(days, 0, -1):
            day_timestamp = now - timedelta(days=day_offset)
            normal_entries = _role_normal_actions(role_name, rng, day_timestamp, user, role_record_ids)
            pending_entries.extend(normal_entries)
            user_normal_count += len(normal_entries)

        anomaly_count = max(1, round(user_normal_count * 0.025))
        anomaly_anchor = now - timedelta(days=rng.randint(0, min(days - 1, 7)))
        anomalous_entries = _role_anomalous_actions(
            role_name,
            rng,
            anomaly_anchor,
            user,
            role_record_ids,
            anomaly_count,
        )
        pending_entries.extend(anomalous_entries)
        summary[role_name]["normal"] += user_normal_count
        summary[role_name]["anomalous"] += len(anomalous_entries)

    pending_entries.sort(key=lambda entry: (entry.timestamp, entry.user_id, entry.action))
    session.add_all(pending_entries)
    session.flush()
    return dict(summary)