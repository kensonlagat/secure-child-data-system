"""The unused placeholder blueprints (/notifications/log, /anomaly/alerts) are gone.

They answered anyone, signed in or not, with placeholder text. Anomaly alerts live in the admin
area; nothing should be served under these two prefixes."""

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import BaseConfig


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    return create_app("testing")


@pytest.mark.parametrize("path", ["/notifications/log", "/anomaly/alerts"])
def test_placeholder_urls_return_404(app, path):
    response = app.test_client().get(path)
    assert response.status_code == 404
    assert b"placeholder" not in response.get_data().lower()


def test_no_routes_registered_under_removed_prefixes(app):
    rules = [rule.rule for rule in app.url_map.iter_rules()]
    assert not [rule for rule in rules if rule.startswith(("/notifications", "/anomaly/"))]
    assert "notifications" not in app.blueprints
    assert "anomaly" not in app.blueprints
