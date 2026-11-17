"""Links between a child and a parent account (#67).

A link gives access only while `status` is active. It starts pending and becomes active only
after an administrator has checked the person's identity offline and confirmed with an OTP
sent to their own phone, bound to the link. Revoking keeps the row; rows are never deleted.
The identity check records the document TYPE only: there is no column for its number.
"""

from datetime import datetime

from app import db

LINK_STATUSES = ("pending", "active", "revoked")
RELATIONSHIPS = ("mother", "father", "guardian", "other")
IDENTITY_DOCUMENT_TYPES = ("national_id", "passport", "birth_certificate", "alien_id", "other")


class GuardianLink(db.Model):
    __tablename__ = "guardian_links"
    __table_args__ = (
        db.CheckConstraint("status IN ('pending', 'active', 'revoked')", name="ck_guardian_link_status"),
        db.CheckConstraint("relationship IN ('mother', 'father', 'guardian', 'other')",
                           name="ck_guardian_link_relationship"),
        db.CheckConstraint("identity_document_type IN ('national_id', 'passport', 'birth_certificate', "
                           "'alien_id', 'other')", name="ck_guardian_link_document_type"),
    )

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False, index=True)
    guardian_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    relationship = db.Column(db.String(20), nullable=False)
    identity_document_type = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="pending")
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    verified_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    revoked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

    guardian = db.relationship("User", foreign_keys=[guardian_user_id])
