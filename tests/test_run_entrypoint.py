"""run.py fails closed when FLASK_ENV is unset (#96)."""

import ast
from pathlib import Path

import pytest

RUN_PY = Path(__file__).resolve().parents[1] / "run.py"


def _select_config_name():
    """Load select_config_name from run.py without executing the module (which builds the app)."""
    tree = ast.parse(RUN_PY.read_text(encoding="utf-8"))
    func = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "select_config_name")
    from app.config import config_by_name

    namespace = {"config_by_name": config_by_name}
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(RUN_PY), "exec"), namespace)
    return namespace["select_config_name"]


@pytest.mark.parametrize("environ", [{}, {"FLASK_ENV": ""}, {"FLASK_ENV": "   "}])
def test_unset_flask_env_selects_production(environ):
    assert _select_config_name()(environ) == "production"


@pytest.mark.parametrize("name", ["development", "production"])
def test_explicit_flask_env_is_respected(name):
    assert _select_config_name()({"FLASK_ENV": name}) == name


@pytest.mark.parametrize("value", ["testing", " testing "])
def test_testing_config_is_refused_outside_the_test_suite(value):
    # TestingConfig disables CSRF, the #73 key checks and the #68 second step at once.
    with pytest.raises(RuntimeError, match="only for the test suite"):
        _select_config_name()({"FLASK_ENV": value})


def test_unknown_flask_env_is_refused():
    with pytest.raises(RuntimeError, match="FLASK_ENV must be one of"):
        _select_config_name()({"FLASK_ENV": "staging"})


def test_production_config_has_debug_off():
    from app.config import ProductionConfig

    assert ProductionConfig.DEBUG is False


def test_run_py_never_forces_debug_on():
    tree = ast.parse(RUN_PY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "run":
            assert not any(keyword.arg == "debug" for keyword in node.keywords)
