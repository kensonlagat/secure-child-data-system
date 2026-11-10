from datetime import date

import pytest

from app.services.record_validation import (
    RecordValidationError,
    validate_record_updates,
)


def test_unknown_field_is_rejected():
    with pytest.raises(RecordValidationError, match="cannot be updated"):
        validate_record_updates({"is_deleted": True})


def test_bad_guardian_contact_is_rejected():
    with pytest.raises(RecordValidationError, match="E.164"):
        validate_record_updates({"guardian_contact": "abc"})


def test_bad_date_is_rejected():
    with pytest.raises(RecordValidationError, match="valid ISO date"):
        validate_record_updates({"date_of_birth": "bad"})


def test_mixed_payload_rejects_without_partial_normalization():
    with pytest.raises(RecordValidationError, match="valid ISO date"):
        validate_record_updates(
            {
                "guardian_contact": "+254700111223",
                "date_of_birth": "bad",
            }
        )


def test_valid_payload_normalizes_values():
    validated = validate_record_updates(
        {
            "full_name": "  Test Child  ",
            "guardian_contact": "  +254700111223  ",
            "date_of_birth": "2014-01-15",
            "medical_notes": "",
        }
    )

    assert validated == {
        "full_name": "Test Child",
        "guardian_contact": "+254700111223",
        "date_of_birth": date(2014, 1, 15),
        "medical_notes": None,
    }