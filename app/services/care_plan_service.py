"""Care plan goals and case notes (#55). Access is decided in access_service.py.
Audit rows carry ids, categories and statuses only, never goal or note text."""

from datetime import date, datetime

from app import db
from app.models.care_plan import GOAL_STATUSES, NOTE_CATEGORIES, CarePlanGoal, CaseNote
from app.services.audit_service import log_action

GOAL_MAX = 500
NOTE_MAX = 4000
LEGAL_SUMMARY_MAX = 500


class CarePlanError(ValueError):
    """Invalid input. The message is safe to show."""


def _date(raw, label, *, allow_future):
    try:
        value = date.fromisoformat((raw or "").strip())
    except ValueError as error:
        raise CarePlanError(f"Enter the {label}.") from error
    if not allow_future and value > date.today():
        raise CarePlanError(f"The {label} can't be in the future.")
    return value


def add_goal(actor, child, form):
    goal = (form.get("goal") or "").strip()
    if not goal or len(goal) > GOAL_MAX:
        raise CarePlanError(f"Describe the goal (up to {GOAL_MAX} characters).")
    entry = CarePlanGoal(child_record_id=child.id, goal=goal,
                         review_date=_date(form.get("review_date"), "review date", allow_future=True),
                         created_by=actor.id)
    db.session.add(entry)
    db.session.flush()
    log_action(user_id=actor.id, action="care_goal_added", target_record_type="child_record",
               target_record_id=child.id, details=f"Added care plan goal {entry.id}")
    return entry


def update_goal(actor, goal, form):
    status = (form.get("status") or "").strip()
    if status not in GOAL_STATUSES:
        raise CarePlanError("Choose open, achieved or discontinued.")
    review_date = _date(form.get("review_date"), "review date", allow_future=True)
    changed = [name for name, value in (("status", status), ("review_date", review_date))
               if getattr(goal, name) != value]
    if not changed:
        return []
    goal.status, goal.review_date = status, review_date
    goal.updated_by, goal.updated_at = actor.id, datetime.utcnow()
    log_action(user_id=actor.id, action="care_goal_updated", target_record_type="child_record",
               target_record_id=goal.child_record_id,
               details=f"Updated goal {goal.id}: {', '.join(changed)} (status {status})")
    return changed


def add_note(actor, child, form):
    category = (form.get("category") or "").strip()
    body = (form.get("body") or "").strip()
    legal_summary = (form.get("legal_summary") or "").strip()
    if category not in NOTE_CATEGORIES:
        raise CarePlanError("Choose a note category.")
    if not body or len(body) > NOTE_MAX:
        raise CarePlanError(f"Write the note (up to {NOTE_MAX} characters).")
    if len(legal_summary) > LEGAL_SUMMARY_MAX:
        raise CarePlanError(f"Keep the legal summary under {LEGAL_SUMMARY_MAX} characters.")
    note = CaseNote(child_record_id=child.id, note_date=_date(form.get("note_date"), "note date", allow_future=False),
                    category=category, body=body, legal_summary=legal_summary or None, author_id=actor.id)
    db.session.add(note)
    db.session.flush()
    log_action(user_id=actor.id, action="case_note_added", target_record_type="child_record",
               target_record_id=child.id,
               details=f"Added {category} case note {note.id}" + (" with a legal summary" if legal_summary else ""))
    return note


def goals(child_record_id):
    return CarePlanGoal.query.filter_by(child_record_id=child_record_id).order_by(CarePlanGoal.review_date).all()


def notes(child_record_id):
    return (CaseNote.query.filter_by(child_record_id=child_record_id)
            .order_by(CaseNote.note_date.desc(), CaseNote.id.desc()).all())


def legal_summaries(child_record_id):
    return [n for n in notes(child_record_id) if n.legal_summary]


def overdue_goals_query():
    """Open goals past their review date, for the home manager overview (#61)."""
    return CarePlanGoal.query.filter(CarePlanGoal.status == "open", CarePlanGoal.review_date < date.today())
