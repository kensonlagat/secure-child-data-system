"""Legal status change requests for the two-person approval workflow."""

from datetime import datetime

from app import db


VALID_LEGAL_STATUSES = {"in_state_care", "eligible_for_adoption", "placed"}


class LegalStatusChangeRequest(db.Model):
    __tablename__ = "legal_status_change_requests"

    id = db.Column(db.Integer, primary_key=True)
    child_record_id = db.Column(db.Integer, db.ForeignKey("child_records.id"), nullable=False)
    requested_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    current_status = db.Column(db.String(50), nullable=False)
    requested_status = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    requester_otp_event_id = db.Column(db.Integer, db.ForeignKey("otp_events.id"), nullable=True)
    approved_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approver_otp_event_id = db.Column(db.Integer, db.ForeignKey("otp_events.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    child_record = db.relationship("ChildRecord")
    requested_by_user = db.relationship("User", foreign_keys=[requested_by_user_id])
    approved_by_user = db.relationship("User", foreign_keys=[approved_by_user_id])
    requester_otp_event = db.relationship("OTPEvent", foreign_keys=[requester_otp_event_id])
    approver_otp_event = db.relationship("OTPEvent", foreign_keys=[approver_otp_event_id])

    def __repr__(self):
        return (
            f"<LegalStatusChangeRequest id={self.id} child_record_id={self.child_record_id} "
            f"status={self.status}>"
        )