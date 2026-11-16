"""Subkeys for keyed hashes, and refusing weak or missing keys at startup (#73)."""

import hashlib
import hmac

import pytest

from app import create_app
from app.config import BaseConfig, DevelopmentConfig, ProductionConfig, TestingConfig
from app.services.key_derivation import derive_subkey, keyed_hash

GOOD_SECRET = "s" * 48
GOOD_FIELD_KEY = "f" * 44


def raw_secret_hmac(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


# --- Subkeys ----------------------------------------------------------------------


def test_subkeys_differ_per_purpose_and_from_the_secret_key():
    app = create_app("testing")
    with app.app_context():
        audit, phone = derive_subkey("audit-identifier"), derive_subkey("change-phone-context")
        assert audit != phone
        assert app.config["SECRET_KEY"].encode() not in (audit, phone)


def test_unknown_purpose_is_refused():
    app = create_app("testing")
    with app.app_context(), pytest.raises(ValueError):
        derive_subkey("audit-identifer")  # typo must not create a new key


def test_unknown_login_identifier_uses_the_subkey_and_stays_stable():
    from app.blueprints.auth.routes import _audit_identifier

    app = create_app("testing")
    with app.test_request_context():
        first = _audit_identifier("ghost@example.com", None)
        second = _audit_identifier("ghost@example.com", None)
        old_style = "unknown:" + raw_secret_hmac(app.config["SECRET_KEY"], "ghost@example.com")[:40]

        assert first == second  # lockout can still count repeats
        assert first == "unknown:" + keyed_hash("audit-identifier", "ghost@example.com")[:40]
        assert first != old_style  # no longer keyed with SECRET_KEY itself
        assert _audit_identifier("known@example.com", object()) == "known@example.com"


def test_phone_change_context_uses_the_subkey():
    from app.blueprints.admin.user_routes import _change_phone_context

    app = create_app("testing")
    with app.app_context():
        context = _change_phone_context("+254733333333")
        old_style = "change_phone:" + raw_secret_hmac(app.config["SECRET_KEY"], "change_phone|+254733333333")[:32]

        assert context == "change_phone:" + keyed_hash("change-phone-context", "+254733333333")[:32]
        assert context != old_style
        assert len(context) <= 50  # fits otp_events.action_context


# --- Startup refusal ---------------------------------------------------------------


@pytest.fixture()
def keys(monkeypatch):
    """Set SECRET_KEY / FIELD_ENCRYPTION_KEY on every config class for one test."""
    monkeypatch.setattr(ProductionConfig, "SQLALCHEMY_DATABASE_URI", "sqlite://", raising=False)
    monkeypatch.setattr(DevelopmentConfig, "SQLALCHEMY_DATABASE_URI", "sqlite://", raising=False)

    def set_keys(secret=GOOD_SECRET, field_key=GOOD_FIELD_KEY):
        for cls in (BaseConfig, DevelopmentConfig, ProductionConfig, TestingConfig):
            monkeypatch.setattr(cls, "SECRET_KEY", secret, raising=False)
            monkeypatch.setattr(cls, "FIELD_ENCRYPTION_KEY", field_key, raising=False)

    return set_keys


@pytest.mark.parametrize("secret", [None, "", "change-me-in-env-file", "short-but-not-default"])
def test_production_refuses_a_missing_default_or_short_secret_key(keys, secret):
    keys(secret=secret)
    with pytest.raises(RuntimeError, match="SECRET_KEY") as error:
        create_app("production")
    if secret:
        assert secret not in str(error.value)  # never echo the value


def test_production_starts_with_a_long_secret_key_and_a_field_key(keys):
    keys()
    assert create_app("production") is not None


def test_debug_accepts_the_default_secret_key(keys):
    keys(secret="change-me-in-env-file")
    assert create_app("development") is not None


@pytest.mark.parametrize("config_name", ["production", "development"])
@pytest.mark.parametrize("field_key", [None, "", "   "])
def test_missing_field_encryption_key_is_refused_in_every_mode_but_testing(keys, config_name, field_key):
    keys(field_key=field_key)
    with pytest.raises(RuntimeError, match="FIELD_ENCRYPTION_KEY"):
        create_app(config_name)


def test_testing_starts_without_any_keys(keys):
    keys(secret=None, field_key=None)
    assert create_app("testing") is not None
