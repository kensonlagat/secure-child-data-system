"""Test helpers for the class link (#48). Call inside an app context."""

from datetime import date

from app import db
from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass, split_class_label


def get_class(label="Grade 6A", year=2026, active=True):
    name, stream = split_class_label(label)
    school_class = SchoolClass.query.filter_by(name=name, stream=stream, academic_year=year).first()
    if school_class is None:
        school_class = SchoolClass(name=name, stream=stream, academic_year=year, is_active=active)
        db.session.add(school_class)
        db.session.flush()
    return school_class


def put_in_class(label="Grade 6A", children=(), teachers=(), year=2026):
    """Enrol the children and assign the teachers to the class. Flushes, does not commit."""
    school_class = get_class(label, year)
    for child in children:
        db.session.add(Enrolment(child_record_id=child.id, class_id=school_class.id,
                                 started_on=date(2026, 1, 1), reason="enrolled"))
    for teacher in teachers:
        db.session.add(ClassTeacherAssignment(class_id=school_class.id, user_id=teacher.id))
    db.session.flush()
    return school_class
