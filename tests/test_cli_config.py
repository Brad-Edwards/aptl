"""Tests for `aptl config show` and `aptl config validate`.

Covers CLI-002 (Pydantic Configuration Validation) and CLI-007
(Configuration Inspection Command).
"""

import json

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app


@pytest.fixture
def runner():
    # Click >=8.2 separates stderr from stdout by default.
    return CliRunner()


VALID_CONFIG = {
    "lab": {"name": "test-lab"},
    "containers": {"wazuh": True, "kali": True, "victim": False},
    "deployment": {"provider": "docker-compose", "project_name": "mylab"},
}


def _write_config(tmp_path, payload):
    path = tmp_path / "aptl.json"
    if isinstance(payload, str):
        path.write_text(payload)
    else:
        path.write_text(json.dumps(payload))
    return path


# ---------------------------------------------------------------------------
# config validate (CLI-002)
# ---------------------------------------------------------------------------


class TestConfigValidate:
    """CLI-002: validate aptl.json with Pydantic."""

    def test_validate_succeeds_on_valid_config(self, runner, tmp_path):
        _write_config(tmp_path, VALID_CONFIG)
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "OK" in result.stdout

    def test_validate_fails_when_file_missing(self, runner, tmp_path):
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "no aptl.json found" in result.stderr.lower()

    def test_validate_fails_on_invalid_json(self, runner, tmp_path):
        _write_config(tmp_path, "{not-json")
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "json" in result.stderr.lower()

    def test_validate_fails_on_missing_required_field(self, runner, tmp_path):
        # `lab.name` is required.
        _write_config(tmp_path, {"lab": {}})
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        # Pydantic includes the field path in the error message.
        assert "name" in result.stderr.lower()

    def test_validate_fails_on_type_error(self, runner, tmp_path):
        # Pydantic v2 will coerce "yes"/"true" strings to bool, so use a
        # value that genuinely can't be a bool (a list).
        _write_config(
            tmp_path,
            {"lab": {"name": "test"}, "containers": {"wazuh": [1, 2]}},
        )
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "wazuh" in result.stderr.lower() or "bool" in result.stderr.lower()

    def test_validate_fails_on_unknown_provider(self, runner, tmp_path):
        _write_config(
            tmp_path,
            {"lab": {"name": "test"}, "deployment": {"provider": "k8s"}},
        )
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "provider" in result.stderr.lower()

    def test_validate_fails_on_empty_lab_name(self, runner, tmp_path):
        _write_config(tmp_path, {"lab": {"name": "   "}})
        result = runner.invoke(
            app, ["config", "validate", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# config show (CLI-007)
# ---------------------------------------------------------------------------


class TestConfigShow:
    """CLI-007: show resolved AptlConfig with defaults."""

    def test_show_succeeds_on_valid_config(self, runner, tmp_path):
        _write_config(tmp_path, VALID_CONFIG)
        result = runner.invoke(
            app, ["config", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "test-lab" in result.stdout
        # Defaults for unset nested fields render too.
        assert "docker-compose" in result.stdout

    def test_show_fails_when_file_missing(self, runner, tmp_path):
        result = runner.invoke(
            app, ["config", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "no aptl.json found" in result.stderr.lower()

    def test_show_fails_on_invalid_json(self, runner, tmp_path):
        _write_config(tmp_path, "{not-json")
        result = runner.invoke(
            app, ["config", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0

    def test_show_fails_on_pydantic_violation(self, runner, tmp_path):
        _write_config(
            tmp_path,
            {"lab": {"name": "test"}, "deployment": {"provider": "k8s"}},
        )
        result = runner.invoke(
            app, ["config", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0

    def test_show_json_output_is_machine_readable(self, runner, tmp_path):
        _write_config(tmp_path, VALID_CONFIG)
        result = runner.invoke(
            app,
            [
                "config",
                "show",
                "--project-dir",
                str(tmp_path),
                "--json",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert parsed["lab"]["name"] == "test-lab"
        # Defaults filled in by Pydantic.
        assert parsed["lab"]["network_subnet"] == "172.20.0.0/16"
        assert parsed["deployment"]["provider"] == "docker-compose"
        # All four top-level groups present.
        assert {"lab", "containers", "deployment", "run_storage"}.issubset(
            parsed.keys()
        )

    def test_show_renders_all_top_level_groups(self, runner, tmp_path):
        _write_config(tmp_path, VALID_CONFIG)
        result = runner.invoke(
            app, ["config", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        for label in ("lab", "containers", "deployment", "run_storage"):
            assert label in result.stdout
