"""Anomaly alert model for flagged audit-log entries."""

from datetime import datetime

from app import db


class AnomalyAlert(db.Model):
    __tablename__ = "anomaly_alerts"

    id = db.Column(db.Integer, primary_key=True)
    audit_log_entry_id = db.Column(
        db.Integer,
        db.ForeignKey("audit_log_entries.id"),
        nullable=False,
        unique=True,
    )
    role_name = db.Column(db.String(50), nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="new")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    audit_log_entry = db.relationship("AuditLogEntry")

    def __repr__(self):
        return (
            f"<AnomalyAlert audit_log_entry_id={self.audit_log_entry_id} "
            f"role_name={self.role_name} status={self.status}>"
        )