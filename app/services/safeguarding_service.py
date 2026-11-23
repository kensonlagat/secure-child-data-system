"""Safeguarding concerns (#62). Access is decided in access_service.py.

The narrative and action notes never appear in audit rows, flash messages, SMS or the
administrator's metadata. Every audit row names concern ids, types and counts only.
"""

from datetime import datetime, timedelta

from sqlalchemy import text

from app import db
from app.models.child_record import ChildRecord
from app.models.encryption import UNREADABLE
from app.models.safeguarding import (
    ACTION_BODY_LIMIT,
    ACTION_TYPES,
    CONCERN_MODES,
    NARRATIVE_LIMIT,
    REFERRAL_AGENCIES,
    URGENCIES,
    SafeguardingConcern,
    SafeguardingConcernAction,
)
from app.models.user import Role, User
from app.services.access_service import is_safeguarding_lead_for
from app.services.audit_service import log_action

LEAD_SMS = "A new safeguarding concern has been raised. Sign in to view it."
NO_LEAD_SMS = "A new safeguarding concern has been raised. Sign in to view it. No safeguarding lead is set."
# D62.4 (approved design note): leads get an SMS for high and immediate concerns; the rest wait in
# their list. With no lead in the mode, administrators get an SMS for every concern, so a concern
# never goes nowhere.
LEAD_SMS_URGENCIES = ("high", "immediate")
UNTRIAGED_AFTER = timedelta(hours=24)
MODE_LABELS = {"school": "School", "childrens_home": "Children's home"}
# Statuses a "status_change" action may move to. "referred" is deliberately absent: it is reached
# only through a referral action, which records the agency. "closed" only through a closure.
STATUS_FLOW = {"open": ("triaged",), "triaged": (), "referred": ("triaged",)}
LINK_REFUSED_ACTION = "concern_link_refused"


class ConcernError(ValueError):
    """Invalid input. The message is safe to show (it never contains the narrative)."""


def _audit(actor, action, concern, details):
    log_action(user_id=actor.id, action=action, target_record_type="safeguarding_concern",
               target_record_id=concern.id, details=details)


def _child_part(concern):
    return f"child record {concern.child_record_id}" if concern.child_record_id else "no child linked"


# --- Leads --------------------------------------------------------------------------------------


def active_leads(mode, exclude_user_id=None):
    users = (User.query.join(Role, Role.id == User.role_id)
             .filter(User.is_active.is_(True), User.is_safeguarding_lead.is_(True), Role.institution_mode == mode,
                     Role.name.notin_(("administrator", "parent_guardian"))).all())
    return [u for u in users if u.id != exclude_user_id and is_safeguarding_lead_for(u, mode)]


def modes_without_lead(exclude_user_id=None):
    """Modes with no active lead, or (with exclude_user_id) none other than that user."""
    return [mode for mode in CONCERN_MODES if not active_leads(mode, exclude_user_id=exclude_user_id)]


# --- Raising ------------------------------------------------------------------------------------


def raise_concern(actor, record, mode, form):
    """Save first (log_action commits), then notify. A failed SMS never loses the concern.
    Returns (concern, notified), where notified is what notify() returned."""
    urgency = (form.get("urgency") or "").strip()
    if urgency not in URGENCIES:
        raise ConcernError("Choose how urgent this is.")
    narrative = (form.get("narrative") or "").strip()
    if not narrative:
        raise ConcernError("Describe what you saw or were told.")
    if len(narrative) > NARRATIVE_LIMIT:
        raise ConcernError(f"Keep the description under {NARRATIVE_LIMIT} characters.")
    if mode not in CONCERN_MODES:
        raise ConcernError("Choose whether this is about a school or children's home child.")
    now = datetime.utcnow()
    concern = SafeguardingConcern(child_record_id=record.id if record else None, institution_mode=mode,
                                  reporter_id=actor.id, involves_staff=form.get("involves_staff") == "yes",
                                  urgency=urgency, status="open", narrative=narrative, created_at=now,
                                  updated_at=now)
    db.session.add(concern)
    db.session.flush()
    _audit(actor, "concern_raised", concern,
           f"Concern {concern.id} raised ({mode}, {urgency}, {_child_part(concern)}"
           f"{', involves staff' if concern.involves_staff else ''})")
    notified = notify(actor, concern)
    return concern, notified


def notify(actor, concern):
    """Tell whoever can act on the concern. Returns "lead" when at least one lead other than the
    reporter exists (they see it in their list, with an SMS for high and immediate), otherwise
    "administrators" (SMS to every active administrator). The reporter never counts as a lead
    for their own concern, because they can't read it (can_read_concern)."""
    from app.services.sms_service import send_sms

    leads = active_leads(concern.institution_mode, exclude_user_id=actor.id)
    if leads:
        if concern.urgency not in LEAD_SMS_URGENCIES:
            _audit(actor, "concern_notified", concern,
                   f"Concern {concern.id}: {len(leads)} lead(s); no SMS for {concern.urgency} (D62.4)")
            return "lead"
        recipients, message, who = leads, LEAD_SMS, "lead"
    else:
        recipients = (User.query.join(Role, Role.id == User.role_id)
                      .filter(Role.name == "administrator", User.is_active.is_(True)).all())
        message, who = NO_LEAD_SMS, "administrator (no safeguarding lead set)"
    sent = failed = 0
    for user in recipients:
        try:
            send_sms(user.phone_number, message)
            sent += 1
        except Exception:  # never lose the concern over an SMS; the failure is audited below
            failed += 1
    _audit(actor, "concern_notified", concern,
           f"Concern {concern.id}: {who} SMS sent {sent}, failed {failed}, recipients {len(recipients)}")
    if failed or not recipients:
        _audit(actor, "concern_notification_failed", concern,
               f"Concern {concern.id}: {failed} of {len(recipients)} {who} SMS failed")
    return "lead" if leads else "administrators"


# --- Reading (leads) ------------------------------------------------------------------------------


def lead_queue(user, modes):
    """Concerns in the lead's mode that they didn't report. No narrative is read here."""
    # Deliberate (lead decision, batch 7): no archived/deleted filter on the child. Concerns stay
    # visible to leads after the child is archived; only raising or linking a new one is refused.
    if not modes:
        return []
    return (SafeguardingConcern.query
            .filter(SafeguardingConcern.institution_mode.in_(modes), SafeguardingConcern.reporter_id != user.id)
            .order_by(SafeguardingConcern.status == "closed", SafeguardingConcern.created_at.desc()).all())


def own_concerns(user):
    return (SafeguardingConcern.query.filter_by(reporter_id=user.id)
            .order_by(SafeguardingConcern.created_at.desc()).all())


def actions_for(concern):
    return (SafeguardingConcernAction.query.filter_by(concern_id=concern.id)
            .order_by(SafeguardingConcernAction.created_at, SafeguardingConcernAction.id).all())


def read_for_lead(actor, concern):
    """Decrypt the narrative and the action log for a lead. Exactly one concern_narrative_viewed
    row per call (never bounded); an integrity failure writes concern_integrity_failed."""
    narrative = concern.narrative
    actions = actions_for(concern)
    _audit(actor, "concern_narrative_viewed", concern, f"Concern {concern.id} read; {_child_part(concern)}")
    unreadable = sum(1 for value in [narrative] + [a.body for a in actions] if value == UNREADABLE)
    if unreadable:
        _audit(actor, "concern_integrity_failed", concern,
               f"Concern {concern.id}: {unreadable} entr{'y' if unreadable == 1 else 'ies'} failed the integrity check")
    return narrative, actions


def child_name(concern):
    """The linked child's name for a lead. On PostgreSQL the lead's own role may not see the child
    row, so a SECURITY DEFINER function returns the encrypted name only for leads of the mode."""
    if concern.child_record_id is None:
        return None
    if db.session.get_bind().dialect.name == "postgresql":
        column_type = ChildRecord.__table__.c.full_name.type
        statement = text("SELECT safeguarding_child_name(:id) AS full_name").columns(full_name=column_type)
        return db.session.execute(statement, {"id": concern.id}).scalar()
    record = db.session.get(ChildRecord, concern.child_record_id)
    return record.full_name if record else None


def _link_target_ok(child_id, mode):
    if db.session.get_bind().dialect.name == "postgresql":
        return bool(db.session.execute(text("SELECT safeguarding_link_target_ok(:c, :m)"),
                                       {"c": child_id, "m": mode}).scalar())
    record = db.session.get(ChildRecord, child_id)
    return (record is not None and record.institution_mode == mode and not record.is_deleted
            and not record.is_archived)


# --- Acting (leads) --------------------------------------------------------------------------------


def _body(form, required, label):
    value = (form.get("body") or "").strip()
    if required and not value:
        raise ConcernError(f"Enter {label}.")
    if len(value) > ACTION_BODY_LIMIT:
        raise ConcernError(f"Keep the note under {ACTION_BODY_LIMIT} characters.")
    return value or None


def add_action(actor, concern, form):
    if concern.status == "closed":
        raise ConcernError("This concern is closed.")
    action_type = (form.get("action_type") or "").strip()
    if action_type not in ACTION_TYPES:
        raise ConcernError("Choose what you are recording.")
    now = datetime.utcnow()
    agency = None
    before = concern.status
    if action_type == "note":
        body = _body(form, True, "the note")
    elif action_type == "status_change":
        new_status = (form.get("status") or "").strip()
        if new_status not in STATUS_FLOW.get(concern.status, ()):
            raise ConcernError("Choose a valid next status.")
        body = _body(form, False, "a note")
        concern.status = new_status
    elif action_type == "referral":
        agency = (form.get("referral_agency") or "").strip()
        if agency not in REFERRAL_AGENCIES:
            raise ConcernError("Choose who the concern was referred to.")
        body = _body(form, False, "a note")
        concern.status = "referred"
    else:  # closure
        body = _body(form, True, "the reason for closing")
        concern.status, concern.closed_at, concern.closed_by = "closed", now, actor.id
    concern.updated_at = now
    db.session.add(SafeguardingConcernAction(concern_id=concern.id, actor_id=actor.id, action_type=action_type,
                                             body=body, referral_agency=agency, created_at=now))
    db.session.flush()
    _audit(actor, "concern_action_added", concern, f"Concern {concern.id}: {action_type} added")
    if concern.status != before:
        _audit(actor, "concern_status_changed", concern, f"Concern {concern.id}: {before} -> {concern.status}")
    if action_type == "referral":
        _audit(actor, "concern_referred", concern, f"Concern {concern.id}: referred to {agency}")
    if action_type == "closure":
        _audit(actor, "concern_closed", concern, f"Concern {concern.id} closed")


MAX_RECORD_ID = 2_147_483_647  # child_records.id is an INTEGER column


def _audit_link_refused(actor, concern, reason):
    """One concern_link_refused row per refused attempt, capped like access_denied: at most
    ACCESS_DENIED_RECORD_CAP_PER_WINDOW rows per user per window. The details name the concern
    and the attempted record number only; free text the user typed is never written, since
    it could be a child's name. Auditing never stops the refusal."""
    from flask import current_app

    from app.services.audit_service import audit_stats

    try:
        window = timedelta(seconds=current_app.config.get("ACCESS_DENIED_AUDIT_WINDOW_SECONDS", 60))
        recent, _ = audit_stats(LINK_REFUSED_ACTION, since=datetime.utcnow() - window, user_id=actor.id,
                                target_type="safeguarding_concern")
        if recent >= current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"]:
            return
        _audit(actor, LINK_REFUSED_ACTION, concern, f"Concern {concern.id}: link refused, {reason}")
    except Exception:  # noqa: BLE001 - same as audit_access_denied: the refusal must still happen
        db.session.rollback()
        current_app.logger.warning("Could not audit a refused concern link")


def link_child(actor, concern, raw_child_id):
    """Set the child once, while it is NULL. Re-linking is refused and audited (a database
    trigger refuses it too)."""
    if concern.child_record_id is not None:
        _audit(actor, "concern_relink_refused", concern,
               f"Concern {concern.id}: already linked to child record {concern.child_record_id}")
        raise ConcernError("This concern is already linked to a child, and that can't be changed.")
    try:
        child_id = int(str(raw_child_id).strip())
    except (TypeError, ValueError) as error:
        _audit_link_refused(actor, concern, "attempted value is not a number")
        raise ConcernError("Enter the child's record number.") from error
    if not 0 < child_id <= MAX_RECORD_ID or not _link_target_ok(child_id, concern.institution_mode):
        _audit_link_refused(actor, concern, f"attempted record {child_id}: no current record in this mode")
        raise ConcernError("No current record with that number in this concern's mode.")
    concern.child_record_id, concern.updated_at = child_id, datetime.utcnow()
    db.session.flush()
    _audit(actor, "concern_child_linked", concern, f"Concern {concern.id} linked to child record {child_id}")


# --- Administrators: metadata only -------------------------------------------------------------------


def admin_rows():
    """The ONLY data administrators get: reporter, time, status, mode and the staff flag (D62.2).
    Built field by field, so there is no narrative, urgency, child or action body to leak."""
    rows = (db.session.query(SafeguardingConcern.id, SafeguardingConcern.created_at, SafeguardingConcern.status,
                             SafeguardingConcern.institution_mode, SafeguardingConcern.involves_staff,
                             User.full_name)
            .join(User, User.id == SafeguardingConcern.reporter_id)
            .order_by(SafeguardingConcern.created_at.desc()).all())
    return [{"id": r[0], "raised_at": r[1].isoformat(timespec="minutes"), "status": r[2], "mode": r[3],
             "involves_staff": bool(r[4]), "reporter": r[5]} for r in rows]


def unreadable_counts():
    """Per mode: concerns not yet closed that no lead can read, because every active lead in the
    mode is the reporter (or there is no lead at all). Counts only, no ids or names."""
    counts = {}
    for mode in CONCERN_MODES:
        lead_ids = [lead.id for lead in active_leads(mode)]
        query = SafeguardingConcern.query.filter(SafeguardingConcern.institution_mode == mode,
                                                 SafeguardingConcern.status != "closed")
        if len(lead_ids) == 1:
            query = query.filter(SafeguardingConcern.reporter_id == lead_ids[0])
        counts[mode] = query.count() if len(lead_ids) <= 1 else 0
    return counts


def untriaged_counts():
    cutoff = datetime.utcnow() - UNTRIAGED_AFTER
    return {mode: SafeguardingConcern.query.filter(SafeguardingConcern.institution_mode == mode,
                                                   SafeguardingConcern.status == "open",
                                                   SafeguardingConcern.created_at < cutoff).count()
            for mode in CONCERN_MODES}
