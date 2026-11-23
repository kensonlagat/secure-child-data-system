"""`flask seed-demo` safety rails. Nothing here touches a database: every refusal must happen first."""

import pytest

from app import create_app
from app.demo_seed import DemoSeedError, check_guards

PASSWORD_VALUE = "demo-pass-for-tests-only"
GOOD = {
    "DEMO_PASSWORD": PASSWORD_VALUE,
    "AFRICASTALKING_USERNAME": "sandbox",
    "DB_SETUP_URL": "postgresql://postgres@localhost:5432/postgres",
    "MIGRATION_DATABASE_URL": "postgresql://cds_owner@localhost:5432/child_data_system",
    "DATABASE_URL": "postgresql://cds_app@localhost:5432/child_data_system",
    "FLASK_ENV": "development",
}
CONFIG = {"SESSION_COOKIE_SECURE": False, "AT_USERNAME": "sandbox"}


def test_good_settings_pass():
    check_guards(GOOD, CONFIG, "child_data_system_demo")


@pytest.mark.parametrize("environ, config, name, message", [
    (GOOD, CONFIG, "child_data_system", "must end in _demo"),
    (GOOD, CONFIG, "child_data_system_demo2", "must end in _demo"),
    ({**GOOD, "FLASK_ENV": "production"}, CONFIG, "x_demo", "production"),
    (GOOD, {**CONFIG, "SESSION_COOKIE_SECURE": True}, "x_demo", "production"),
    ({**GOOD, "AFRICASTALKING_USERNAME": "live-account"}, CONFIG, "x_demo", "sandbox"),
    # Fail closed: a missing value refuses, in the environment or in the app config.
    ({k: v for k, v in GOOD.items() if k != "AFRICASTALKING_USERNAME"}, CONFIG, "x_demo", "sandbox"),
    ({**GOOD, "AFRICASTALKING_USERNAME": ""}, CONFIG, "x_demo", "sandbox"),
    (GOOD, {"SESSION_COOKIE_SECURE": False}, "x_demo", "sandbox"),
    (GOOD, {**CONFIG, "AT_USERNAME": "live-account"}, "x_demo", "sandbox"),
    ({k: v for k, v in GOOD.items() if k != "DEMO_PASSWORD"}, CONFIG, "x_demo", "DEMO_PASSWORD"),
    ({**GOOD, "DEMO_PASSWORD": "short"}, CONFIG, "x_demo", "DEMO_PASSWORD"),
    ({k: v for k, v in GOOD.items() if k != "DB_SETUP_URL"}, CONFIG, "x_demo", "DB_SETUP_URL"),
    ({**GOOD, "DATABASE_URL": "postgresql://cds_app@localhost:5432/x_demo"}, CONFIG, "x_demo", "normally uses"),
    ({**GOOD, "MIGRATION_DATABASE_URL": "postgresql://cds_owner@localhost:5432/x_demo"}, CONFIG, "x_demo",
     "normally uses"),
])
def test_refusals(environ, config, name, message):
    with pytest.raises(DemoSeedError, match=message):
        check_guards(environ, config, name)


@pytest.fixture()
def cli(monkeypatch):
    connected = []
    monkeypatch.setattr("psycopg2.connect", lambda *a, **k: connected.append(1) or (_ for _ in ()).throw(
        RuntimeError("no database in tests")))
    app = create_app("testing")
    return app, connected


def _invoke(app, args):
    with app.app_context():
        return app.test_cli_runner().invoke(args=args)


def test_cli_refuses_before_touching_any_database(cli, monkeypatch):
    app, connected = cli
    for key, value in GOOD.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AFRICASTALKING_USERNAME", "live-account")
    result = _invoke(app, ["seed-demo"])
    assert result.exit_code != 0 and "sandbox" in result.output
    assert connected == []
    assert PASSWORD_VALUE not in result.output


def test_cli_refuses_a_non_demo_name(cli, monkeypatch):
    app, connected = cli
    for key, value in GOOD.items():
        monkeypatch.setenv(key, value)
    result = _invoke(app, ["seed-demo", "--demo-database", "child_data_system"])
    assert result.exit_code != 0 and "_demo" in result.output and connected == []


def test_seed_only_refuses_when_database_url_is_not_the_demo_database(cli, monkeypatch):
    app, connected = cli
    for key, value in GOOD.items():
        monkeypatch.setenv(key, value)
    result = _invoke(app, ["seed-demo", "--seed-only"])  # testing DB is SQLite in memory
    assert result.exit_code != 0 and "does not point at the demo database" in result.output
    assert PASSWORD_VALUE not in result.output


def test_child_process_errors_are_shown_with_credentials_masked(cli, monkeypatch):
    """A failing step's output may contain a connection URL. The ClickException text must mask it."""
    import subprocess

    app, connected = cli
    for key, value in GOOD.items():
        monkeypatch.setenv(key, value)
    marker = "marker-Pw-9f3k"

    class FakeCursor:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, *args):
            pass

    class FakeConnection:
        autocommit = False

        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr("psycopg2.connect", lambda *a, **k: FakeConnection())
    failure = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=(
        f"sqlalchemy.exc.OperationalError: could not connect to "
        f"postgresql+psycopg2://cds_owner:{marker}@localhost:5432/child_data_system_demo\n"
        f"also tried postgresql://postgres:{marker}@localhost/postgres with {PASSWORD_VALUE}"))
    monkeypatch.setattr("app.demo_seed.subprocess.run", lambda *a, **k: failure)

    result = _invoke(app, ["seed-demo"])

    assert result.exit_code != 0 and "migrate as owner failed" in result.output
    assert marker not in result.output and PASSWORD_VALUE not in result.output
    assert "cds_owner:***@localhost" in result.output and "postgres:***@localhost" in result.output


def test_scrub_masks_url_credentials_only():
    from app.demo_seed import scrub

    assert scrub("postgresql://u:p%40ss@h/db and https://x.test/path") == "postgresql://u:***@h/db and https://x.test/path"
    assert scrub("no secrets here") == "no secrets here"
    assert scrub("value s3cret!", secrets=("s3cret!",)) == "value ***"
