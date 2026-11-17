"""OTP-protected export requests (#65). Each request fixes what will be exported (type,
target, columns) before the code is sent; the code is bound to the request id and to a hash
of those parameters, so it can't release a different export. Single use."""

from datetime import datetime

from app import db

EXPORT_TYPES = ("child_file", "class_list")


class ExportRequest(db.Model):
    __tablename__ = "export_requests"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    export_type = db.Column(db.String(20), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    columns = db.Column(db.String(500), nullable=False)  # comma-separated field names (no data)
    params_hash = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="pending")  # pending, completed
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
