from unittest.mock import Mock

from app import create_app


def test_test_sms_rejects_invalid_phone_without_sending(monkeypatch):
    app = create_app("testing")
    runner = app.test_cli_runner()
    send_sms = Mock()
    monkeypatch.setattr("app.cli.send_sms", send_sms)

    result = runner.invoke(app.cli.commands["test-sms"], ["--to", "0711111111"])

    assert result.exit_code != 0
    assert "E.164" in result.output
    send_sms.assert_not_called()


def test_test_sms_reports_recipient_status(monkeypatch):
    app = create_app("testing")
    runner = app.test_cli_runner()
    monkeypatch.setenv("AFRICASTALKING_USERNAME", "sandbox")
    monkeypatch.setenv("AFRICASTALKING_API_KEY", "configured")
    monkeypatch.setattr(
        "app.cli.send_sms",
        lambda phone_number, message: {
            "SMSMessageData": {
                "Recipients": [
                    {"number": phone_number, "statusCode": "100", "status": "Sent"}
                ]
            }
        },
    )

    result = runner.invoke(app.cli.commands["test-sms"], ["--to", "+254711111111"])

    assert result.exit_code == 0
    assert "username set: yes" in result.output
    assert "api key set: yes" in result.output
    assert "statusCode: 100" in result.output
    assert "configured" not in result.output


def test_test_sms_prints_error_type_only(monkeypatch):
    app = create_app("testing")
    runner = app.test_cli_runner()

    def failing_send(phone_number, message):
        raise ConnectionError("https://api.example/?apiKey=leaked-value")

    monkeypatch.setattr("app.cli.send_sms", failing_send)

    result = runner.invoke(app.cli.commands["test-sms"], ["--to", "+254711111111"])

    assert "send failed: ConnectionError" in result.output
    assert "leaked-value" not in result.output
