"""Classes, teacher assignments and enrolments (#48).

These replace the free-text `users.assigned_class` and `child_records.class_assigned`
columns for scoping. Rows are closed (ended_at / ended_on), never deleted, so the
history stays complete and the app's database role still needs no DELETE.
"""

import re
from datetime import datetime

from sqlalchemy import text

from app import db

ENROLMENT_REASONS = ("enrolled", "moved", "promoted", "migrated")
END_REASONS = ("moved", "promoted", "left")
_LABEL_PATTERN = re.compile(r"^(.*\d)\s*([A-Za-z])$")  # "Grade 6A" -> "Grade 6", "A"


def split_class_label(label):
    """Split a free-text class label into (name, stream). Unparseable labels keep the
    whole text as the name with an empty stream, so nothing is lost."""
    label = (label or "").strip()
    match = _LABEL_PATTERN.match(label)
    if match:
        return match.group(1).strip(), match.group(2).upper()
    return label, ""


class SchoolClass(db.Model):
    __tablename__ = "school_classes"
    __table_args__ = (db.UniqueConstraint("name", "stream", "academic_year", name="uq_school_classes_name_stream_year"),)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    stream = db.Column(db.String(10), nullable=False, default="", server_default="")
    academic_year = db.Column(db.Integer, nullable=False)
    # Archived classes (is_active false) grant no teacher access.
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @property
    def label(self):
        return f"{self.name}{self.stream}"

    def __repr__(self):
        return f"<SchoolClass id={self.id} {self.label} {self.academic_year}>"


class ClassTeacherAssignment(db.Model):
    __tablename__ = "class_teacher_assignments"

    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("school_classes.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    assigned_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)  # null = current

    school_class = db.relationship("SchoolClass")
    user = db.relationship("User")


class Enrolment(db.Model):
    __tablename__ = "enrolments"
    __table_args__ = (
        # Backstop for the application check: at most one current enrolment per child.
        db.Index(
            "uq_enrolments_one_current",
            "child_record_id",
            unique=True,
            postgresql_where=text("ended_on IS NULL"),
            sqlite_where=text("ended_on IS NULL"),
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    class_id = db.Column(db.Integer, db.ForeignKey("school_classes.id"), nullable=False, index=True)
    started_on = db.Column(db.Date, nullable=False)
    ended_on = db.Column(db.Date, nullable=True)  # null = current
    reason = db.Column(db.String(20), nullable=False)  # why it started (ENROLMENT_REASONS)
    end_reason = db.Column(db.String(20), nullable=True)  # why it ended (END_REASONS)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # null for the migration

    school_class = db.relationship("SchoolClass")
    child_record = db.relationship("ChildRecord")
