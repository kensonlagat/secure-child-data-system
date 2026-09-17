"""Audit Log Entry model — the tamper-proof accountability record.

Critical design constraint from your proposal: entries must be insert-only.
No route, service, or admin action should ever call db.session.delete() or
issue an UPDATE against this table. We enforce this two ways:
  1. Application layer: no update/delete methods exposed anywhere in the
     codebase for this model (convention + code review).
  2. Database layer (do this in Sprint 5): a PostgreSQL rule or trigger
     that rejects UPDATE/DELETE on this table outright, so even a bug or
     a direct psql session can't violate it. This is what makes the log
     "tamper-proof" rather than just "conventionally append-only".
"""

from datetime import datetime

from app import db


class AuditLogEntry(db.Model):
    __tablename__ = "audit_log_entries"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="audit_entries")

    action = db.Column(db.String(50), nullable=False)
    # e.g. "view", "create", "update", "delete", "export", "login", "login_failed"

    target_record_type = db.Column(db.String(50))
    # e.g. "child_record", "user", "legal_status"
    target_record_id = db.Column(db.Integer)

    details = db.Column(db.Text)
    # short human-readable context, e.g. "updated medical_notes field"

    ip_address = db.Column(db.String(45))
    is_synthetic = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<AuditLogEntry user={self.user_id} action={self.action} at={self.timestamp}>"
