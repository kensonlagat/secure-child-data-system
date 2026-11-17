"""
Entry point. Run with: python run.py
Loads .env first so app/config.py can read the environment variables.

Fails closed (#96): without an explicit FLASK_ENV the production config is used (debug
off, and the #73 checks refuse weak keys). Local development sets FLASK_ENV=development
in .env. Debug mode comes only from the chosen config, never from this file.
"""
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app
from app.config import config_by_name


def select_config_name(environ):
    """Return the config name from FLASK_ENV, defaulting to production. Unknown names are refused."""
    name = (environ.get("FLASK_ENV") or "").strip() or "production"
    if name == "testing":
        # TestingConfig turns off CSRF, the #73 key checks and the #68 second step. It is
        # only for the test suite, which calls create_app("testing") directly.
        raise RuntimeError("FLASK_ENV=testing is refused: testing is only for the test suite.")
    if name not in config_by_name:
        raise RuntimeError(f"FLASK_ENV must be one of: {', '.join(sorted(config_by_name))}.")
    return name


app = create_app(select_config_name(os.environ))

if __name__ == "__main__":
    app.run()  # debug follows the config (DevelopmentConfig.DEBUG), never forced on here
