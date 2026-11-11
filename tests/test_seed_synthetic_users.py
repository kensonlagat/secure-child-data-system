"""seed-synthetic-users: a random password per run, written only to the ignored local file."""

import re

import pytest
from werkzeug.security import check_password_hash

from app import create_app, db
from app.models.audit_log import AuditLogEntry
from app.models.user import Role, User

PAIR = re.compile(r"`([^`@\s]+@[^`\s]+)` / `([^`]+)`")
OLD_HARDCODED = "Synthetic" + "#2026"  # the value that is in public git history


@pytest.fixture()
def app(tmp_path, monkeypatch):
    application = create_app("testing")
    credentials = tmp_path / "TESTING_CREDENTIALS.md"
    credentials.write_text("# Testing Credentials\n", encoding="utf-8")
    monkeypatch.setattr("app.cli._credentials_file_path", lambda: str(credentials))
    monkeypatch.setattr("app.cli._is_git_ignored", lambda path: True)
    with application.app_context():
        db.create_all()
        for name, mode in (("administrator", "both"), ("teacher", "school"), ("legal_officer", "childrens_home")):
            db.session.add(Role(name=name, institution_mode=mode))
        db.session.commit()
    application.config["CREDENTIALS"] = credentials
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def seed(app, per_role=1):
    with app.app_context():
        return app.test_cli_runner().invoke(args=["seed-synthetic-users", "--per-role", str(per_role)])


def written_pairs(app):
    return dict(PAIR.findall(app.config["CREDENTIALS"].read_text(encoding="utf-8")))


def test_seeded_accounts_use_the_password_written_to_the_local_file(app):
    result = seed(app, per_role=2)

    assert result.exit_code == 0, result.output
    pairs = written_pairs(app)
    assert len(pairs) == 6
    with app.app_context():
        for email, password in pairs.items():
            user = User.query.filter_by(email=email).one()
            assert check_password_hash(user.password_hash, password)
            assert not check_password_hash(user.password_hash, OLD_HARDCODED)


def test_password_is_never_printed(app):
    result = seed(app)

    for password in written_pairs(app).values():
        assert password not in result.output
    assert "not shown" in result.output


def test_each_run_gets_a_different_password(app):
    seed(app)
    first = set(written_pairs(app).values())
    seed(app)
    both = set(written_pairs(app).values())

    assert len(first) == 1 and len(both) == 2  # one password per run, different each run


def test_refuses_when_the_credentials_file_is_not_git_ignored(app, monkeypatch):
    monkeypatch.setattr("app.cli._is_git_ignored", lambda path: False)

    result = seed(app)

    assert result.exit_code != 0
    assert "not git-ignored" in result.output
    assert written_pairs(app) == {}
    with app.app_context():
        assert User.query.count() == 0


def test_failed_file_write_leaves_accounts_with_an_unknown_password(app, monkeypatch):
    def broken(path, emails, password):
        raise PermissionError("read-only")

    monkeypatch.setattr("app.cli._append_credentials", broken)

    result = seed(app)

    assert result.exit_code != 0
    assert "password is unknown" in result.output
    with app.app_context():
        for user in User.query.all():
            assert not check_password_hash(user.password_hash, OLD_HARDCODED)


def test_seeding_is_audited_without_the_password(app):
    seed(app, per_role=2)

    with app.app_context():
        rows = AuditLogEntry.query.filter_by(action="seed_synthetic_users").all()
        assert [row.details for row in rows] == ["Created 6 synthetic accounts"]
        assert rows[0].attempted_identifier == "cli:seed-synthetic-users"
    password = next(iter(written_pairs(app).values()))
    assert password not in rows[0].details


def test_git_ignore_check_fails_closed_when_git_is_unavailable(monkeypatch, tmp_path):
    from app import cli

    def no_git(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(cli.subprocess, "run", no_git)
    assert cli._is_git_ignored(str(tmp_path / "TESTING_CREDENTIALS.md")) is False


def test_the_real_credentials_file_is_git_ignored():
    from app import cli

    app = create_app("testing")
    with app.app_context():
        assert cli._is_git_ignored(cli._credentials_file_path()) is True
