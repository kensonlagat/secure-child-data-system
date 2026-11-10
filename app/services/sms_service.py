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


def send_sms(phone_number: str, message: str) -> dict:
    """Send a single SMS. Returns the Africa's Talking API response dict."""
    try:
        username = os.environ.get("AFRICASTALKING_USERNAME", "sandbox")
        api_key = os.environ.get("AFRICASTALKING_API_KEY")
        response = requests.post(
            "https://api.sandbox.africastalking.com/version1/messaging",
            headers={
                "Accept": "application/json",
                "User-Agent": "child-data-system-sms/1.0",
                "apiKey": api_key or "",
            },
            data={
                "username": username,
                "to": phone_number,
                "message": message,
                "bulkSMSMode": 1,
            },
            timeout=15,
            impersonate="chrome",
        )
        response.raise_for_status()
        return response.json()
    except Exception as error:
        logger.error("SMS send failed with %s", type(error).__name__)
        raise
