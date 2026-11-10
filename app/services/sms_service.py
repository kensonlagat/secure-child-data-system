"""
Wraps the Africa's Talking API for both OTP delivery and parent/guardian
notifications. Keeping this as one service (not scattered inline calls)
means Sprint 1 (OTP) and Sprint 6 (Notifications) both build on the same
tested foundation.
"""

import logging
import os

from curl_cffi import requests

logger = logging.getLogger(__name__)
SMS_TIMEOUT_SECONDS = 15  # See issue #26: external SMS calls need an explicit timeout.
SUCCESS_STATUS_CODES = {"100", "101", "102"}


class SmsConfigError(RuntimeError):
    """Raised when SMS delivery configuration is incomplete."""


class SmsDeliveryError(RuntimeError):
    """Raised when Africa's Talking reports a failed recipient delivery."""

    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f"SMS delivery failed with status code {status_code}.")


def _messaging_url(username):
    """Return the Africa's Talking messaging endpoint for the account mode."""
    host = (
        "api.sandbox.africastalking.com"
        if username == "sandbox"
        else "api.africastalking.com"
    )
    return f"https://{host}/version1/messaging"


def send_sms(phone_number: str, message: str) -> dict:
    """Send a single SMS. Returns the Africa's Talking API response dict."""
    username = os.environ.get("AFRICASTALKING_USERNAME", "sandbox")
    api_key = os.environ.get("AFRICASTALKING_API_KEY")
    if not api_key or not api_key.strip():
        raise SmsConfigError("AFRICASTALKING_API_KEY is not configured.")

    try:
        response = requests.post(
            _messaging_url(username),
            headers={
                "Accept": "application/json",
                "User-Agent": "child-data-system-sms/1.0",
                "apiKey": api_key,
            },
            data={
                "username": username,
                "to": phone_number,
                "message": message,
                "bulkSMSMode": 1,
            },
            timeout=SMS_TIMEOUT_SECONDS,
            verify=True,  # Certificate verification must never be disabled.
        )
        response.raise_for_status()
        payload = response.json()
        recipients = payload.get("SMSMessageData", {}).get("Recipients", [])
        for recipient in recipients:
            status_code = str(recipient.get("statusCode"))
            if status_code not in SUCCESS_STATUS_CODES:
                raise SmsDeliveryError(status_code)
        return payload
    except Exception as error:
        logger.error("SMS send failed with %s", type(error).__name__)
        raise
