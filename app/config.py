"""
Centralized configuration. Values come from environment variables (.env),
never hardcoded — especially secrets and the encryption key.

Load order: python-dotenv reads .env into os.environ at process start
(see run.py), then these classes read from os.environ.
"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-env-file")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Field-level encryption key for sensitive child record columns.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    FIELD_ENCRYPTION_KEY = os.environ.get("FIELD_ENCRYPTION_KEY")

    # Africa's Talking (SMS / OTP)
    AT_USERNAME = os.environ.get("AFRICASTALKING_USERNAME", "sandbox")
    AT_API_KEY = os.environ.get("AFRICASTALKING_API_KEY")

    OTP_LENGTH = 6
    OTP_EXPIRY = timedelta(minutes=5)

    # Session/cookie hardening — relevant since this handles sensitive data
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # allow http on localhost


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL", "sqlite:///:memory:"
    )
    WTF_CSRF_ENABLED = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # requires HTTPS


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
