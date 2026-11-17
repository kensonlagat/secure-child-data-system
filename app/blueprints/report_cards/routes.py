"""Term report cards (#70). Class teachers enter and publish their own class's reports;
principals and administrators read. Anything out of scope answers 404, audited (bounded).
Archived children never appear. Published reports are read-only."""

from datetime import date

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.middleware.rbac import audit_access_denied
from app.models.report_card import COMPETENCY_LEVELS, LEARNING_AREAS, TERMS, ReportCard
from app.models.school_class import ClassTeacherAssignment, SchoolClass
from app.services import report_card_service as reports
from app.services.access_service import (can_enter_marks, can_read_class_reports, can_read_report_card,
                                         get_record_for_report_card)
from app.services.attendance_service import class_children
from app.services.audit_service import log_action

report_cards_bp = Blueprint("report_cards", __name__, template_folder="../../templates")


def _deny(details, target_type, target_id, status=404):
    audit_access_denied(details, status_code=status, target_record_type=target_type, target_record_id=target_id,
                        actor_cap=current_app.config["ACCESS_DENIED_RECORD_CAP_PER_WINDOW"])
    abort(status)


def _class_or_404(class_id):
    school_class = db.session.get(SchoolClass, class_id)
    if school_class is None or not can_read_class_reports(current_user, school_class):
        _deny("Denied report card class access", "school_class", class_id)
    return school_class


def _term_args(source):
    try:
        return reports.parse_term(source.get("year") or date.today().year, source.get("term") or 1)
    except reports.ReportCardError:
        abort(400)


@report_cards_bp.route("/")
@login_required
def class_list():
    role = getattr(current_user.role, "name", None)
    if role == "teacher":
        classes = (SchoolClass.query.join(ClassTeacherAssignment, ClassTeacherAssignment.class_id == SchoolClass.id)
                   .filter(ClassTeacherAssignment.user_id == current_user.id, ClassTeacherAssignment.ended_at.is_(None),
                           SchoolClass.is_active.is_(True)).all())
    elif role in ("administrator", "principal"):
        classes = SchoolClass.query.filter_by(is_active=True).order_by(SchoolClass.name, SchoolClass.stream).all()
    else:
        audit_access_denied("Denied report card access", status_code=403)
        abort(403)
    return render_template("report_cards/classes.html", classes=classes, year=date.today().year, terms=TERMS)


@report_cards_bp.route("/classes/<int:class_id>")
@login_required
def class_reports(class_id):
    school_class = _class_or_404(class_id)
    year, term = _term_args(request.args)
    children = class_children(school_class)  # archived and deleted children excluded
    cards = reports.cards_for_class(school_class, year, term)
    log_action(user_id=current_user.id, action="report_cards_class_viewed", target_record_type="school_class",
               target_record_id=school_class.id, details=f"Report cards {year} term {term}")
    return render_template("report_cards/class.html", school_class=school_class, year=year, term=term,
                           terms=TERMS, children=children, cards=cards,
                           can_enter={child.id: can_enter_marks(current_user, school_class, child) for child in children})


def _entry_context(class_id, record_id):
    school_class = _class_or_404(class_id)
    record = get_record_for_report_card(current_user, record_id)
    if record is None or not can_enter_marks(current_user, school_class, record):
        _deny("Denied report card entry", "child_record", record_id)
    return school_class, record


@report_cards_bp.route("/classes/<int:class_id>/children/<int:record_id>", methods=["GET"])
@login_required
def edit(class_id, record_id):
    school_class, record = _entry_context(class_id, record_id)
    year, term = _term_args(request.args)
    card = reports.get_card(record.id, year, term)
    if card is not None and card.is_published:
        return redirect(url_for("report_cards.view_card", card_id=card.id))
    return render_template("report_cards/edit.html", school_class=school_class, record=record, year=year, term=term,
                           card=card, entries={e.learning_area: e for e in card.entries} if card else {},
                           areas=LEARNING_AREAS, levels=COMPETENCY_LEVELS)


@report_cards_bp.route("/classes/<int:class_id>/children/<int:record_id>", methods=["POST"])
@login_required
def save(class_id, record_id):
    school_class, record = _entry_context(class_id, record_id)
    year, term = _term_args(request.form)
    try:
        card = reports.save_draft(current_user, school_class, record, year, term, request.form)
    except reports.ReportCardError as error:
        db.session.rollback()
        log_action(user_id=current_user.id, action="report_card_save_refused", target_record_type="child_record",
                   target_record_id=record.id, details=f"Refused report card save for {year} term {term}")
        flash(str(error), "error")
        return redirect(url_for("report_cards.edit", class_id=class_id, record_id=record_id, year=year, term=term))
    if request.form.get("publish") == "1":
        try:
            reports.publish(current_user, card)
            flash("Report card published. It can no longer be changed.", "success")
            return redirect(url_for("report_cards.view_card", card_id=card.id))
        except reports.ReportCardError as error:
            db.session.rollback()
            flash(str(error), "error")
    else:
        flash("Draft saved.", "success")
    return redirect(url_for("report_cards.edit", class_id=class_id, record_id=record_id, year=year, term=term))


@report_cards_bp.route("/cards/<int:card_id>")
@login_required
def view_card(card_id):
    card = db.session.get(ReportCard, card_id)
    record = get_record_for_report_card(current_user, card.child_record_id) if card is not None else None
    if card is None or record is None or not can_read_report_card(current_user, record):
        _deny("Denied report card view", "report_card", card_id)
    # Bounded: one view row per user and card per window, however often it is reopened or printed.
    audit_access_denied("Viewed report card", status_code=200, target_record_type="report_card",
                        target_record_id=card.id, action="report_card_viewed")
    school_class = db.session.get(SchoolClass, card.class_id)
    return render_template("report_cards/card.html", card=card, record=record, school_class=school_class,
                           entries={e.learning_area: e for e in card.entries}, areas=LEARNING_AREAS,
                           levels=dict(COMPETENCY_LEVELS),
                           can_edit=not card.is_published and can_enter_marks(current_user, school_class, record))
