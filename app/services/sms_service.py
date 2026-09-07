"""
Wraps the Africa's Talking API for both OTP delivery and parent/guardian
notifications. Keeping this as one service (not scattered inline calls)
means Sprint 1 (OTP) and Sprint 6 (Notifications) both build on the same
tested foundation.
"""
import os
import africastalking


def _get_sms_client():
    africastalking.initialize(
        username=os.environ.get("AFRICASTALKING_USERNAME", "sandbox"),
        api_key=os.environ.get("AFRICASTALKING_API_KEY"),
    )
    return africastalking.SMS


def send_sms(phone_number: str, message: str) -> dict:
    """Send a single SMS. Returns the Africa's Talking API response dict."""
    sms = _get_sms_client()
    response = sms.send(message, [phone_number])
    # TODO (Sprint 6): log this send in the notifications table regardless
    # of success/failure, per the "all notifications logged" requirement.
    return response
