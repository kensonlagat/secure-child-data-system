"""
OTP Event model — tracks one-time password challenges for sensitive actions
(legal status change, bulk export, record deletion), per your Authentication
Module spec. Also gives the Anomaly Detection module a source for one of its
flagged patterns: "multiple failed OTP verification attempts in a session".
"""
from datetime import datetime, timedelta
from app import db


class OTPEvent(db.Model):
    __tablename__ = "otp_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    action_context = db.Column(db.String(50), nullable=False)
    # what triggered the OTP, e.g. "legal_status_change", "bulk_export", "delete_record"
    target_record_id = db.Column(db.Integer)

    code_hash = db.Column(db.String(255), nullable=False)
    # never store the raw OTP — hash it the same way you'd hash a password

    is_verified = db.Column(db.Boolean, default=False)
    attempt_count = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def __repr__(self):
        return f"<OTPEvent user={self.user_id} context={self.action_context}>"
