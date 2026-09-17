"""
Importing all models here ensures Flask-Migrate/Alembic can discover them
when generating migrations (`flask db migrate`). Always import new models
in this file as you add them.
"""
from app.models.user import User, Role
from app.models.child_record import ChildRecord
from app.models.audit_log import AuditLogEntry
from app.models.otp_event import OTPEvent
from app.models.legal_status_change_request import LegalStatusChangeRequest

__all__ = ["User", "Role", "ChildRecord", "AuditLogEntry", "OTPEvent", "LegalStatusChangeRequest"]
