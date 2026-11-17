"""Term report cards (#70).

Field allowlist: a save reads only `level_<area>` and `comment_<area>` for the known learning
areas, plus `teacher_comment`. Every other submitted key is ignored, so a crafted form can't
set status, class, child, term or authorship. Published cards are refused here and, on
PostgreSQL, by a trigger. Audit rows name counts and areas, never levels or comments.
"""

from datetime import datetime

from app import db
from app.models.report_card import (COMPETENCY_LEVEL_KEYS, LEARNING_AREA_KEYS, TERMS, ReportCard,
                                    ReportCardEntry)
from app.services.audit_service import log_action

MAX_AREA_COMMENT = 300
MAX_TEACHER_COMMENT = 1000
MIN_YEAR, MAX_YEAR = 2020, 2100


class ReportCardError(ValueError):
    """Invalid input or a refused change. The message is safe to show."""


def parse_term(raw_year, raw_term):
    try:
        year, term = int(raw_year), int(raw_term)
    except (TypeError, ValueError):
        raise ReportCardError("Choose a valid year and term.") from None
    if not MIN_YEAR <= year <= MAX_YEAR or term not in TERMS:
        raise ReportCardError("Choose a valid year and term.")
    return year, term


def get_card(record_id, year, term):
    return ReportCard.query.filter_by(child_record_id=record_id, academic_year=year, term=term).first()


def cards_for_class(school_class, year, term):
    return {card.child_record_id: card for card in
            ReportCard.query.filter_by(class_id=school_class.id, academic_year=year, term=term).all()}


def cards_for_child(record_id):
    return (ReportCard.query.filter_by(child_record_id=record_id)
            .order_by(ReportCard.academic_year.desc(), ReportCard.term.desc()).all())


def _clean_text(value, limit, label):
    text = (value or "").strip()
    if len(text) > limit:
        raise ReportCardError(f"{label} must be at most {limit} characters.")
    return text or None


def save_draft(actor, school_class, record, year, term, form):
    """Create or update a draft card from the allowlisted form fields. Returns the card."""
    card = get_card(record.id, year, term)
    if card is not None and card.is_published:
        raise ReportCardError("This report card is published and can't be changed.")
    if card is not None and card.class_id != school_class.id:
        raise ReportCardError("This child's report for that term belongs to another class.")

    levels, comments = {}, {}
    for area in LEARNING_AREA_KEYS:
        level = (form.get(f"level_{area}") or "").strip()
        if level and level not in COMPETENCY_LEVEL_KEYS:
            raise ReportCardError("Choose a competency level from the list.")
        if level:
            levels[area] = level
        comments[area] = _clean_text(form.get(f"comment_{area}"), MAX_AREA_COMMENT, "Each learning-area comment")
    teacher_comment = _clean_text(form.get("teacher_comment"), MAX_TEACHER_COMMENT, "The teacher's comment")

    now = datetime.utcnow()
    if card is None:
        card = ReportCard(child_record_id=record.id, class_id=school_class.id, academic_year=year, term=term,
                          status="draft", created_by=actor.id, created_at=now, updated_by=actor.id, updated_at=now)
        db.session.add(card)
        db.session.flush()
    existing = {entry.learning_area: entry for entry in card.entries}
    changed = []
    for area in LEARNING_AREA_KEYS:
        entry = existing.get(area)
        if entry is None:
            if area not in levels:
                if comments[area]:
                    raise ReportCardError("Choose a level for every learning area you comment on.")
                continue
            db.session.add(ReportCardEntry(report_card_id=card.id, learning_area=area, level=levels[area],
                                           comment=comments[area], updated_by=actor.id, updated_at=now))
            changed.append(area)
        elif (levels.get(area, entry.level), comments[area]) != (entry.level, entry.comment):
            # A blank level keeps the saved one: entries are never deleted.
            entry.level = levels.get(area, entry.level)
            entry.comment = comments[area]
            entry.updated_by, entry.updated_at = actor.id, now
            changed.append(area)
    if teacher_comment != card.teacher_comment:
        card.teacher_comment = teacher_comment
        changed.append("teacher_comment")
    card.updated_by, card.updated_at = actor.id, now
    db.session.commit()
    log_action(user_id=actor.id, action="report_card_saved", target_record_type="child_record",
               target_record_id=record.id,
               details=f"Draft report {year} term {term} (card {card.id}): {len(changed)} field(s) changed"
                       + (f" ({', '.join(changed)})" if changed else ""))
    return card


def publish(actor, card):
    if card.is_published:
        raise ReportCardError("This report card is already published.")
    missing = [area for area in LEARNING_AREA_KEYS if area not in {e.learning_area for e in card.entries}]
    if missing:
        raise ReportCardError(f"Give a level for every learning area before publishing ({len(missing)} missing).")
    now = datetime.utcnow()
    card.status = "published"
    card.published_by, card.published_at = actor.id, now
    card.updated_by, card.updated_at = actor.id, now
    db.session.commit()
    log_action(user_id=actor.id, action="report_card_published", target_record_type="child_record",
               target_record_id=card.child_record_id,
               details=f"Published report {card.academic_year} term {card.term} (card {card.id})")
    return card
