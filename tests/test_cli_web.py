"""Tests for the web serve CLI command."""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

pytest.importorskip("uvicorn", reason="Web dependencies not installed")


@pytest.fixture
def runner():
    return CliRunner()


class TestWebServe:
    @patch("uvicorn.run")
    def test_serve_default_options(self, mock_run, runner):
        from aptl.cli.web import app

        result = runner.invoke(app, ["--host", "0.0.0.0", "--port", "9000"])

        assert result.exit_code == 0
        assert "Starting APTL web API on 0.0.0.0:9000" in result.output
        mock_run.assert_called_once_with(
            "aptl.api.main:app",
            host="0.0.0.0",
            port=9000,
            reload=False,
            workers=1,
            log_level="info",
            timeout_keep_alive=65,
            access_log=True,
        )

    @patch("uvicorn.run")
    def test_serve_with_project_dir(self, mock_run, runner):
        import os
        from aptl.cli.web import app

        result = runner.invoke(app, ["--project-dir", "/tmp/mylab"])

        assert result.exit_code == 0
        mock_run.assert_called_once()
        assert os.environ.get("APTL_PROJECT_DIR") == "/tmp/mylab"
        # Cleanup
        os.environ.pop("APTL_PROJECT_DIR", None)

    @patch("uvicorn.run")
    def test_serve_with_workers(self, mock_run, runner):
        from aptl.cli.web import app

        result = runner.invoke(app, ["--workers", "4"])

        assert result.exit_code == 0
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["workers"] == 4

    @patch("uvicorn.run")
    def test_serve_with_reload(self, mock_run, runner):
        from aptl.cli.web import app

        result = runner.invoke(app, ["--reload"])

        assert result.exit_code == 0
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["reload"] is True
