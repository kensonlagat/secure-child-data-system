"""Validation for partial child-record updates."""

from datetime import date
import re

from app.models.child_record import ChildRecord
from app.models.user import User

E164_PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")


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
    if not value:
        if required:
            raise RecordValidationError(field_name, f"{field_name} cannot be blank.")
        return None

    if field_name == "guardian_contact" and not E164_PHONE_PATTERN.fullmatch(value):
        raise RecordValidationError(
            field_name,
            "guardian_contact must be a valid E.164 phone number.",
        )

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
        else:
            raise RecordValidationError(field_name, f"{field_name} cannot be updated.")

    return validated
