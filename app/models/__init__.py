"""
Importing all models here ensures Flask-Migrate/Alembic can discover them
when generating migrations (`flask db migrate`). Always import new models
in this file as you add them.
"""
from app.models.user import User, Role
from app.models.child_record import ChildRecord
from app.models.audit_log import AuditLogEntry
from app.models.anomaly_alert import AnomalyAlert
from app.models.otp_event import OTPEvent
from app.models.legal_status_change_request import LegalStatusChangeRequest
from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass
from app.models.consent import ConsentRecord
from app.models.attendance import AbsenceAlert, AttendanceCorrection, AttendanceMark, AttendanceRegister
from app.models.pickup import AuthorisedCollector
from app.models.clinic import ClinicVisit
from app.models.intake import IntakeRecord
from app.models.care_plan import CarePlanGoal, CaseNote
from app.models.court import CourtHearing
from app.models.health import HealthEntry, MedicationAdministration, MedicationSchedule
from app.models.family import FamilyTracing, FamilyVisit
from app.models.placement import AftercareFollowUp, Placement

__all__ = [
	"User",
	"Role",
	"ChildRecord",
	"AuditLogEntry",
	"AnomalyAlert",
	"OTPEvent",
	"LegalStatusChangeRequest",
	"SchoolClass",
	"ClassTeacherAssignment",
	"Enrolment",
	"ConsentRecord",
	"AttendanceRegister",
	"AttendanceMark",
	"AttendanceCorrection",
	"AbsenceAlert",
	"AuthorisedCollector",
	"ClinicVisit",
	"IntakeRecord",
	"CarePlanGoal",
	"CaseNote",
	"CourtHearing",
	"HealthEntry",
	"MedicationSchedule",
	"MedicationAdministration",
	"FamilyVisit",
	"FamilyTracing",
	"Placement",
	"AftercareFollowUp",
]
