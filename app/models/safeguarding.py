"""Safeguarding concerns (#62).

Any staff member raises a concern; designated safeguarding leads (in the concern's mode) read
and act on it. The narrative and every action note are encrypted. Concerns and their action log
are never deleted: the app role may only change a concern's status columns (column-level UPDATE
grants), and the action log is append-only. `child_record_id` may be NULL (D62.1) and can be set
once, by a lead, while it is still NULL.
"""

from datetime import datetime

from app import db
from app.config import BaseConfig
from app.models.encryption import IntegrityCheckedEncryptedType

URGENCIES = ("low", "medium", "high", "immediate")
STATUSES = ("open", "triaged", "referred", "closed")
ACTION_TYPES = ("note", "status_change", "referral", "closure")
REFERRAL_AGENCIES = ("childrens_officer", "police", "health", "other")
CONCERN_MODES = ("school", "childrens_home")
NARRATIVE_LIMIT = 5000
ACTION_BODY_LIMIT = 2000


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


def _in(column, values):
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


class SafeguardingConcern(db.Model):
    __tablename__ = "safeguarding_concerns"
    __table_args__ = (
        db.CheckConstraint(_in("urgency", URGENCIES), name="ck_concern_urgency"),
        db.CheckConstraint(_in("status", STATUSES), name="ck_concern_status"),
        db.CheckConstraint(_in("institution_mode", CONCERN_MODES), name="ck_concern_mode"),
    )

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=True, index=True)
    institution_mode = db.Column(db.String(20), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    involves_staff = db.Column(db.Boolean, nullable=False, default=False)
    urgency = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="open")
    narrative = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)
    closed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class SafeguardingConcernAction(db.Model):
    __tablename__ = "safeguarding_concern_actions"
    __table_args__ = (
        db.CheckConstraint(_in("action_type", ACTION_TYPES), name="ck_concern_action_type"),
        db.CheckConstraint("referral_agency IS NULL OR " + _in("referral_agency", REFERRAL_AGENCIES),
                           name="ck_concern_action_agency"),
    )

    id = db.Column(db.Integer, primary_key=True)
    concern_id = db.Column(db.Integer, db.ForeignKey("safeguarding_concerns.id"), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action_type = db.Column(db.String(20), nullable=False)
    body = db.Column(IntegrityCheckedEncryptedType(db.String, _encryption_key), nullable=True)
    referral_agency = db.Column(db.String(30), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
