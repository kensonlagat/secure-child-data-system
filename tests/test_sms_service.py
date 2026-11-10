from unittest.mock import Mock

import pytest

from app.services import sms_service


def _response(status_code="101"):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "SMSMessageData": {
            "Recipients": [{"statusCode": status_code}],
        }
    }
    return response


def test_successful_recipient_status(monkeypatch):
    response = _response("101")
    post = Mock(return_value=response)
    monkeypatch.setattr(sms_service.requests, "post", post)
    monkeypatch.setenv("AFRICASTALKING_USERNAME", "sandbox")
    monkeypatch.setenv("AFRICASTALKING_API_KEY", "configured")

    result = sms_service.send_sms("+254711111111", "test body")

    assert result["SMSMessageData"]["Recipients"][0]["statusCode"] == "101"
    assert post.call_args.kwargs["verify"] is True
    assert post.call_args.kwargs["timeout"] == 15


def test_failed_recipient_status_raises_without_sensitive_values(monkeypatch):
    post = Mock(return_value=_response("403"))
    monkeypatch.setattr(sms_service.requests, "post", post)
    monkeypatch.setenv("AFRICASTALKING_API_KEY", "configured")

    with pytest.raises(sms_service.SmsDeliveryError) as error:
        sms_service.send_sms("+254711111111", "secret message")

    assert error.value.status_code == "403"
    assert "+254711111111" not in str(error.value)
    assert "secret message" not in str(error.value)


def test_missing_api_key_fails_before_network_call(monkeypatch):
    post = Mock()
    monkeypatch.setattr(sms_service.requests, "post", post)
    monkeypatch.delenv("AFRICASTALKING_API_KEY", raising=False)

    with pytest.raises(sms_service.SmsConfigError):
        sms_service.send_sms("+254711111111", "test body")

    post.assert_not_called()


@pytest.mark.parametrize(
    ("username", "expected_host"),
    [
        ("sandbox", "api.sandbox.africastalking.com"),
        ("production-user", "api.africastalking.com"),
    ],
)
def test_host_selection_by_username(monkeypatch, username, expected_host):
    post = Mock(return_value=_response("100"))
    monkeypatch.setattr(sms_service.requests, "post", post)
    monkeypatch.setenv("AFRICASTALKING_USERNAME", username)
    monkeypatch.setenv("AFRICASTALKING_API_KEY", "configured")

    sms_service.send_sms("+254711111111", "test body")

    assert post.call_args.args[0] == (f"https://{expected_host}/version1/messaging")
