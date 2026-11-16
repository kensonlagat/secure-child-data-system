"""Validation for partial child-record updates."""

from datetime import date
import re

from app.models.child_record import ChildRecord
from app.models.encryption import UNREADABLE
from app.models.user import User

E164_PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")

# Profile fields (#49a).
GENDER_VALUES = {"female", "male", "not_recorded"}
BIRTH_CERTIFICATE_PATTERN = re.compile(r"^[A-Za-z0-9/-]{1,30}$")
LEARNER_UPI_PATTERN = re.compile(r"^[A-Za-z0-9]{1,20}$")
ALLERGIES_MAX_LENGTH = 500
PROFILE_TEXT_RULES = {
    "birth_certificate_number": (BIRTH_CERTIFICATE_PATTERN,
                                 "birth_certificate_number may contain letters, digits, / and -, up to 30 characters."),
    "learner_upi": (LEARNER_UPI_PATTERN, "learner_upi may contain letters and digits, up to 20 characters."),
}


class RecordValidationError(ValueError):
    """Represent a client-correctable child-record field error."""

    def __init__(self, field_name, message):
        super().__init__(message)
        self.field_name = field_name


def _column_max_length(field_name):
    """Return a declared text length when the model defines one."""
    column = getattr(ChildRecord, field_name).property.columns[0]
    return getattr(column.type, "length", None)


def _validate_text(field_name, value, required=False):
    """Normalize and validate a text update."""
    if not isinstance(value, str):
        raise RecordValidationError(field_name, f"{field_name} must be text.")

    value = value.strip()
    if value == UNREADABLE:
        # The placeholder shown for a value that failed its integrity check (#88) must never be
        # saved: it would overwrite the stored ciphertext.
        raise RecordValidationError(field_name, f"{field_name} cannot be set to that value.")
    if not value:
        if required:
            raise RecordValidationError(field_name, f"{field_name} cannot be blank.")
        return None

    if field_name == "guardian_contact" and not E164_PHONE_PATTERN.fullmatch(value):
        raise RecordValidationError(
            field_name,
            "guardian_contact must be a valid E.164 phone number.",
        )

    if field_name in PROFILE_TEXT_RULES:
        pattern, message = PROFILE_TEXT_RULES[field_name]
        if not pattern.fullmatch(value):
            raise RecordValidationError(field_name, message)
    if field_name == "allergies" and len(value) > ALLERGIES_MAX_LENGTH:
        raise RecordValidationError(field_name, f"allergies must be {ALLERGIES_MAX_LENGTH} characters or fewer.")

    max_length = _column_max_length(field_name)
    if max_length is not None and len(value) > max_length:
        raise RecordValidationError(
            field_name,
            f"{field_name} must be {max_length} characters or fewer.",
        )
    return value


def validate_record_updates(payload):
    """Return normalized updates or raise a field-specific validation error."""
    validated = {}

    for field_name, value in payload.items():
        if field_name in {
            "full_name",
            "guardian_contact",
            "medical_notes",
            "birth_certificate_number",
            "learner_upi",
            "allergies",
        }:
            validated[field_name] = _validate_text(
                field_name,
                value,
                required=field_name == "full_name",
            )
        elif field_name == "date_of_birth":
            if not isinstance(value, str) or not value.strip():
                raise RecordValidationError(
                    field_name, "date_of_birth cannot be blank."
                )
            try:
                validated[field_name] = date.fromisoformat(value)
            except ValueError as exc:
                raise RecordValidationError(
                    field_name,
                    "date_of_birth must be a valid ISO date.",
                ) from exc
        elif field_name == "caseload_worker_id":
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise RecordValidationError(
                    field_name,
                    "caseload_worker_id must be null or an integer.",
                )
            if value is not None:
                worker = User.query.filter_by(id=value, is_active=True).first()
                if (
                    worker is None
                    or getattr(worker.role, "name", None) != "social_worker"
                ):
                    raise RecordValidationError(
                        field_name,
                        "caseload_worker_id must reference an active social_worker.",
                    )
            validated[field_name] = value
        elif field_name == "gender":
            if value is None or (isinstance(value, str) and not value.strip()):
                validated[field_name] = None
            elif isinstance(value, str) and value.strip() in GENDER_VALUES:
                validated[field_name] = value.strip()
            else:
                raise RecordValidationError(
                    field_name, f"gender must be one of: {', '.join(sorted(GENDER_VALUES))}."
                )
        else:
            raise RecordValidationError(field_name, f"{field_name} cannot be updated.")

    return validated
