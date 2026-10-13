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


def verify_otp(otp_event: OTPEvent, submitted_code: str) -> bool:
    if otp_event.attempt_count >= MAX_OTP_ATTEMPTS:
        return False

    otp_event.attempt_count += 1
    if otp_event.is_expired():
        db.session.commit()
        return False

    is_valid = check_password_hash(otp_event.code_hash, submitted_code)
    if is_valid:
        otp_event.is_verified = True
    db.session.commit()
    # TODO (Sprint 7): repeated failed attempts here feed the anomaly
    # detection module's "multiple failed OTP" signal.
    return is_valid
