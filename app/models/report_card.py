"""Term report cards (#70), competency-based (CBC).

- One card per child per academic year and term, tied to the class the child was in.
- One entry per learning area, with a competency level and an optional encrypted comment.
  The teacher's overall comment is encrypted too (it is narrative about a child).
- Draft cards can be edited by the class teacher. Once published, a card and its entries are
  read-only: the service refuses, and on PostgreSQL a trigger refuses any change as well
  (so a bug or a direct cds_app session can't edit a published report). There is no delete.
"""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

TERMS = (1, 2, 3)
REPORT_STATUSES = ("draft", "published")
# Kenyan CBC upper-primary learning areas. Keys are stored; labels are shown.
LEARNING_AREAS = (
    ("english", "English"),
    ("kiswahili", "Kiswahili"),
    ("mathematics", "Mathematics"),
    ("science_technology", "Science and Technology"),
    ("social_studies", "Social Studies"),
    ("agriculture_nutrition", "Agriculture and Nutrition"),
    ("creative_arts", "Creative Arts"),
    ("religious_education", "Religious Education"),
    ("physical_health", "Physical and Health Education"),
)
LEARNING_AREA_KEYS = tuple(key for key, _ in LEARNING_AREAS)
# CBC rubric levels.
COMPETENCY_LEVELS = (
    ("EE", "Exceeding expectations"),
    ("ME", "Meeting expectations"),
    ("AE", "Approaching expectations"),
    ("BE", "Below expectations"),
)
COMPETENCY_LEVEL_KEYS = tuple(key for key, _ in COMPETENCY_LEVELS)


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class ReportCard(db.Model):
    __tablename__ = "report_cards"
    __table_args__ = (
        db.UniqueConstraint("child_record_id", "academic_year", "term", name="uq_report_card_term"),
        db.CheckConstraint("status IN ('draft', 'published')", name="ck_report_card_status"),
        db.CheckConstraint("term IN (1, 2, 3)", name="ck_report_card_term"),
    )

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    class_id = db.Column(db.Integer, db.ForeignKey("school_classes.id"), nullable=False, index=True)
    academic_year = db.Column(db.Integer, nullable=False)
    term = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False, default="draft")
    teacher_comment = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    published_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    published_at = db.Column(db.DateTime, nullable=True)

    entries = db.relationship("ReportCardEntry", back_populates="report_card", order_by="ReportCardEntry.id")

    @property
    def is_published(self):
        return self.status == "published"


class ReportCardEntry(db.Model):
    __tablename__ = "report_card_entries"
    __table_args__ = (
        db.UniqueConstraint("report_card_id", "learning_area", name="uq_report_card_entry_area"),
        db.CheckConstraint("level IN ('EE', 'ME', 'AE', 'BE')", name="ck_report_card_entry_level"),
        db.CheckConstraint("learning_area IN (" + ", ".join(f"'{key}'" for key in LEARNING_AREA_KEYS) + ")",
                           name="ck_report_card_entry_area"),
    )

    id = db.Column(db.Integer, primary_key=True)
    report_card_id = db.Column(db.Integer, db.ForeignKey("report_cards.id"), nullable=False, index=True)
    learning_area = db.Column(db.String(40), nullable=False)
    level = db.Column(db.String(2), nullable=False)
    comment = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    report_card = db.relationship("ReportCard", back_populates="entries")
