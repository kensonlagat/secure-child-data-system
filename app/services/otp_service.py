"""
OTP generation, hashing, and verification logic (Sprint 1).
Uses the same hashing approach as passwords — never store or transmit
the raw code in logs.
"""
import secrets
import string
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.config import BaseConfig
from app.models.otp_event import OTPEvent
from app.services.sms_service import send_sms

MAX_OTP_ATTEMPTS = 5


def generate_otp(user, action_context: str, target_record_id: int = None) -> OTPEvent:
    code = "".join(secrets.choice(string.digits) for _ in range(BaseConfig.OTP_LENGTH))

    otp_event = OTPEvent(
        user_id=user.id,
        action_context=action_context,
        target_record_id=target_record_id,
        code_hash=generate_password_hash(code),
        expires_at=datetime.utcnow() + BaseConfig.OTP_EXPIRY,
    )
    db.session.add(otp_event)
    db.session.commit()

    send_sms(user.phone_number, f"Your verification code is {code}. Expires in 5 minutes.")
    return otp_event


def _locked_otp_query(otp_id):
    """Re-read one OTP row with SELECT ... FOR UPDATE, replacing any cached copy.

    On PostgreSQL the row stays locked until the transaction ends, so a second request
    verifying the same code waits here and then sees the first one's result.
    """
    return (
        db.session.query(OTPEvent)
        .filter(OTPEvent.id == otp_id)
        .with_for_update()
        .populate_existing()
    )


def verify_otp(otp_event: OTPEvent, submitted_code: str) -> bool:
    # Lock and re-read the row first. Without the lock, two concurrent requests could both
    # read is_verified=False and both accept the same code, or both read the same
    # attempt_count and push past the attempt limit.
    otp_event = _locked_otp_query(otp_event.id).one_or_none()
    if otp_event is None:
        db.session.commit()  # ends the transaction, as every other path does
        return False

    # Single use, enforced here for every flow: a code that already verified once can
    # never verify again, even if a caller forgets to check is_verified.
    if otp_event.is_verified or otp_event.attempt_count >= MAX_OTP_ATTEMPTS:
        db.session.commit()  # release the row lock; callers commit right after anyway
        return False

    otp_event.attempt_count += 1
    if otp_event.is_expired():
        db.session.commit()
        return False

    is_valid = check_password_hash(otp_event.code_hash, submitted_code)
    if is_valid:
        otp_event.is_verified = True
    db.session.commit()  # commits and releases the row lock
    # TODO (Sprint 7): repeated failed attempts here feed the anomaly
    # detection module's "multiple failed OTP" signal.
    return is_valid
