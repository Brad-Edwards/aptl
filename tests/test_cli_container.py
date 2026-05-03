"""Tests for `aptl container list|logs|shell` (CLI-004)."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def project_dir(tmp_path):
    """An APTL project dir with a minimal valid aptl.json."""
    (tmp_path / "aptl.json").write_text(json.dumps({"lab": {"name": "test"}}))
    return tmp_path


@pytest.fixture
def fake_backend(mocker):
    """Patch ``aptl.cli.container.get_backend`` to return a MagicMock."""
    backend = MagicMock()
    mocker.patch("aptl.cli.container.get_backend", return_value=backend)
    return backend


# ---------------------------------------------------------------------------
# container list
# ---------------------------------------------------------------------------


class TestContainerList:
    def test_list_renders_table_with_containers(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_list.return_value = [
            {"Name": "aptl-victim", "State": "running", "Health": ""},
            {"Name": "aptl-kali", "State": "exited", "Health": ""},
        ]
        result = runner.invoke(
            app, ["container", "list", "--project-dir", str(project_dir)]
        )
        assert result.exit_code == 0
        assert "aptl-victim" in result.stdout
        assert "aptl-kali" in result.stdout
        assert "running" in result.stdout
        assert "exited" in result.stdout
        fake_backend.container_list.assert_called_once_with(all_containers=True)

    def test_list_handles_empty(self, runner, project_dir, fake_backend):
        fake_backend.container_list.return_value = []
        result = runner.invoke(
            app, ["container", "list", "--project-dir", str(project_dir)]
        )
        assert result.exit_code == 0
        assert "no containers" in result.stdout.lower()

    def test_list_fails_when_no_aptl_json(self, runner, tmp_path):
        result = runner.invoke(
            app, ["container", "list", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "no aptl.json" in result.stderr.lower()


# ---------------------------------------------------------------------------
# container logs
# ---------------------------------------------------------------------------


class TestContainerLogs:
    def test_logs_delegates_to_backend(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_logs.return_value = 0
        result = runner.invoke(
            app,
            [
                "container",
                "logs",
                "aptl-victim",
                "--project-dir",
                str(project_dir),
            ],
        )
        assert result.exit_code == 0
        fake_backend.container_logs.assert_called_once_with(
            "aptl-victim", follow=False, tail=None
        )

    def test_logs_passes_follow_and_tail(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_logs.return_value = 0
        result = runner.invoke(
            app,
            [
                "container",
                "logs",
                "aptl-victim",
                "-f",
                "--tail",
                "100",
                "--project-dir",
                str(project_dir),
            ],
        )
        assert result.exit_code == 0
        fake_backend.container_logs.assert_called_once_with(
            "aptl-victim", follow=True, tail=100
        )

    def test_logs_propagates_nonzero_exit(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_logs.return_value = 7
        result = runner.invoke(
            app,
            [
                "container",
                "logs",
                "aptl-missing",
                "--project-dir",
                str(project_dir),
            ],
        )
        assert result.exit_code == 7


# ---------------------------------------------------------------------------
# container shell
# ---------------------------------------------------------------------------


class TestContainerShell:
    def test_shell_delegates_to_backend(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_shell.return_value = 0
        result = runner.invoke(
            app,
            [
                "container",
                "shell",
                "aptl-kali",
                "--project-dir",
                str(project_dir),
            ],
        )
        assert result.exit_code == 0
        fake_backend.container_shell.assert_called_once_with(
            "aptl-kali", shell=None
        )

    def test_shell_passes_explicit_shell(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_shell.return_value = 0
        result = runner.invoke(
            app,
            [
                "container",
                "shell",
                "aptl-alpine",
                "--shell",
                "/bin/sh",
                "--project-dir",
                str(project_dir),
            ],
        )
        assert result.exit_code == 0
        fake_backend.container_shell.assert_called_once_with(
            "aptl-alpine", shell="/bin/sh"
        )

    def test_shell_propagates_nonzero_exit(
        self, runner, project_dir, fake_backend
    ):
        fake_backend.container_shell.return_value = 1
        result = runner.invoke(
            app,
            [
                "container",
                "shell",
                "aptl-victim",
                "--project-dir",
                str(project_dir),
            ],
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


class TestContainerCommandErrorHandling:
    """Shared error paths for the three container subcommands."""

    @pytest.mark.parametrize("cmd", [
        ["container", "list"],
        ["container", "logs", "aptl-victim"],
        ["container", "shell", "aptl-kali"],
    ])
    def test_invalid_config_fails_before_backend(
        self, runner, tmp_path, cmd, mocker
    ):
        # Malformed aptl.json — load_config raises ValueError.
        (tmp_path / "aptl.json").write_text("{not-json")
        backend_factory = mocker.patch("aptl.cli.container.get_backend")
        full = cmd + ["--project-dir", str(tmp_path)]
        result = runner.invoke(app, full)
        assert result.exit_code != 0
        backend_factory.assert_not_called()
