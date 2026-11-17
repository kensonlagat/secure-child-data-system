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
    WTF_CSRF_TIME_LIMIT = None
    LOGIN_MAX_FAILURES = 5
    LOGIN_LOCKOUT_MINUTES = 15
    # Coarse flood guard only: schools share one public IP, so this must stay
    # well above what a busy staff room produces. Per-account lockout does the real work.
    LOGIN_IP_MAX_FAILURES = 100
    # Staff second sign-in step (#68): after the password, a one-time SMS code. Not read
    # from the environment, so it can't be switched off by a setting; create_app refuses
    # to start with it off outside testing.
    STAFF_SECOND_STEP_REQUIRED = True
    # At most one access_denied audit row per actor, endpoint and outcome in this window.
    ACCESS_DENIED_AUDIT_WINDOW_SECONDS = 60
    # On top of the per-record bound: at most this many record-level access_denied rows per
    # user in each window, so cycling through many forbidden records cannot flood the log.
    ACCESS_DENIED_RECORD_CAP_PER_WINDOW = 20
    # CSRF failures (#101) use the same writer and window, with this per-user cap.
    CSRF_FAILURE_AUDIT_CAP_PER_WINDOW = 20

    # Attendance (#50): this many absences within the window send one guardian SMS.
    ATTENDANCE_ABSENCE_THRESHOLD = 3
    ATTENDANCE_ALERT_WINDOW_DAYS = 30

    # Archived records (#64) are kept at least this long after the leave date. Display only:
    # nothing is ever hard-deleted automatically.
    RECORD_RETENTION_YEARS = 7

    # Uploads (#66): requests above this are refused with 413 before the app reads them.
    MAX_CONTENT_LENGTH = 11 * 1024 * 1024

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
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")
    WTF_CSRF_ENABLED = False
    # Older tests sign in with one POST. The #68 tests turn the second step back on.
    STAFF_SECOND_STEP_REQUIRED = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # requires HTTPS


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
