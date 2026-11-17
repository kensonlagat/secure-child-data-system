"""Aggregates for the principal overview (#53). Counts only: no names, no clinical text,
no individual concern details ever leave this module."""

from collections import OrderedDict
from datetime import date, datetime, timedelta

from app import db
from app.models.attendance import ATTENDANCE_STATUSES, AttendanceMark, AttendanceRegister
from app.models.child_record import ChildRecord
from app.models.clinic import ClinicVisit


def attendance_trend(days=14, today=None):
    """{date: {status: count}} for the last `days` days, school-wide, deleted records excluded."""
    today = today or date.today()
    start = today - timedelta(days=days - 1)
    trend = OrderedDict((start + timedelta(days=offset), {status: 0 for status in ATTENDANCE_STATUSES})
                        for offset in range(days))
    rows = (db.session.query(AttendanceRegister.register_date, AttendanceMark.status, db.func.count(AttendanceMark.id))
            .join(AttendanceMark, AttendanceMark.register_id == AttendanceRegister.id)
            .join(ChildRecord, ChildRecord.id == AttendanceMark.child_record_id)
            .filter(AttendanceRegister.register_date >= start, AttendanceRegister.register_date <= today,
                    ChildRecord.is_deleted.is_(False))
            .group_by(AttendanceRegister.register_date, AttendanceMark.status).all())
    for register_date, status, count in rows:
        trend[register_date][status] = count
    return trend


def clinic_activity(weeks=4, now=None):
    """[(week starting, visit count)] for the last `weeks` weeks (Monday-based), school records only."""
    now = now or datetime.now()
    this_monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    result = []
    for offset in range(weeks - 1, -1, -1):
        week_start = this_monday - timedelta(weeks=offset)
        count = (ClinicVisit.query.join(ChildRecord, ChildRecord.id == ClinicVisit.child_record_id)
                 .filter(ClinicVisit.visited_at >= week_start, ClinicVisit.visited_at < week_start + timedelta(weeks=1),
                         ChildRecord.institution_mode == "school", ChildRecord.is_deleted.is_(False))
                 .count())
        result.append((week_start.date(), count))
    return result


def open_concerns_count():
    """Open safeguarding concerns (#62). None until concern reporting exists."""
    return None
