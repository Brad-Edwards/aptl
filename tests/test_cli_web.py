"""Tests for the web serve CLI command."""

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

pytest.importorskip("uvicorn", reason="Web dependencies not installed")


@pytest.fixture
def runner():
    return CliRunner()


class TestWebServe:
    @pytest.fixture(autouse=True)
    def _pin_asset_root(self):
        """Pin a resolvable GUI asset root for serve-start mechanics tests.

        These tests exercise serve-start behaviour (worker clamp, reload
        passthrough, project dir, uvicorn kwargs) — not GUI-asset resolution.
        Without this, ``aptl web serve`` now fails hard (exit 1) when no build
        is present, so the suite would pass locally only when an untracked
        ``web/build`` happens to exist and fail in CI. Pinning a fake root makes
        these tests deterministic regardless of the ambient build state; the
        fail-hard / API-only / real-resolution branches are covered explicitly
        in TestWebServeWebRoot.
        """
        import os

        with patch(
            "aptl.cli.web.get_web_asset_root",
            return_value=Path("/fake/web/build"),
        ):
            yield
        os.environ.pop("APTL_WEB_ROOT", None)

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
    def test_serve_rejects_workers_option(self, mock_run, runner):
        """There is deliberately no --workers flag: the in-process session,
        one-time launch token, and ticket stores are not shared across workers,
        so the server is always single-worker and the flag would be a footgun."""
        from aptl.cli.web import app

        result = runner.invoke(app, ["--workers", "4"])

        assert result.exit_code != 0
        mock_run.assert_not_called()

    @patch("uvicorn.run")
    def test_serve_is_always_single_worker(self, mock_run, runner):
        """uvicorn is always launched with a single worker."""
        from aptl.cli.web import app

        result = runner.invoke(app, [])

        assert result.exit_code == 0
        assert mock_run.call_args[1]["workers"] == 1

    @patch("uvicorn.run")
    def test_serve_with_reload(self, mock_run, runner):
        from aptl.cli.web import app

        result = runner.invoke(app, ["--reload"])

        assert result.exit_code == 0
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["reload"] is True

    @patch("uvicorn.run")
    def test_login_url_uses_bind_address_by_default(self, mock_run, runner):
        """Without --public-origin, the login URL points at the bind host:port."""
        from aptl.cli.web import app

        result = runner.invoke(app, ["--host", "127.0.0.1", "--port", "8400"])

        assert result.exit_code == 0
        assert "http://127.0.0.1:8400/api/auth/login?token=" in result.output

    @patch("uvicorn.run")
    def test_public_origin_overrides_login_url(self, mock_run, runner):
        """--public-origin prints the login URL for the browser-facing origin.

        Models the split aptl-web-api + aptl-web-ui delivery where the API binds
        :8400 but the operator's browser uses the Caddy UI origin (:3000).
        """
        from aptl.cli.web import app

        result = runner.invoke(
            app,
            ["--host", "0.0.0.0", "--port", "8400", "--public-origin", "http://127.0.0.1:3000"],
        )

        assert result.exit_code == 0
        assert "http://127.0.0.1:3000/api/auth/login?token=" in result.output
        assert "http://127.0.0.1:8400/api/auth/login" not in result.output

    @patch("uvicorn.run")
    def test_public_origin_from_env(self, mock_run, runner):
        """APTL_WEB_PUBLIC_ORIGIN env sets the login origin (compose split profile)."""
        from aptl.cli.web import app

        result = runner.invoke(
            app,
            ["--port", "8400"],
            env={"APTL_WEB_PUBLIC_ORIGIN": "http://127.0.0.1:3000"},
        )

        assert result.exit_code == 0
        assert "http://127.0.0.1:3000/api/auth/login?token=" in result.output


class TestWebServeWebRoot:
    """Tests for the --web-root option."""

    @patch("uvicorn.run")
    def test_web_root_resolves_valid_dir(self, mock_run, runner, tmp_path):
        """--web-root pointing to a dir with index.html is accepted."""
        root = tmp_path / "build"
        root.mkdir()
        (root / "index.html").write_text("<html/>")

        from aptl.cli.web import app
        import os

        result = runner.invoke(app, ["--web-root", str(root)])

        assert result.exit_code == 0, result.output
        assert f"Serving GUI from {root}" in result.output
        assert os.environ.get("APTL_WEB_ROOT") == str(root)
        # Cleanup
        os.environ.pop("APTL_WEB_ROOT", None)

    @patch("uvicorn.run")
    def test_missing_assets_without_api_only_fails_hard(
        self, mock_run, runner, tmp_path
    ):
        """No resolvable assets and no --api-only → fatal error (exit 1).

        The shipped single-origin contract serves the GUI from this process; a
        missing build is a configuration error, not a silent degrade.
        """
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        from aptl.cli.web import app

        # Patch get_web_asset_root so it returns None when explicit dir has no index.
        # The real fallback would search other candidates; we isolate just this path.
        with patch(
            "aptl.cli.web.get_web_asset_root",
            return_value=None,
        ):
            result = runner.invoke(app, ["--web-root", str(empty_dir)])

        assert result.exit_code == 1, result.output
        assert "GUI cannot be served" in result.output
        # The server must NOT have been started.
        mock_run.assert_not_called()

    @patch("uvicorn.run")
    def test_no_candidates_without_api_only_fails_hard(self, mock_run, runner):
        """Without --web-root, no candidates, and no --api-only → fatal error."""
        from aptl.cli.web import app

        with patch(
            "aptl.cli.web.get_web_asset_root",
            return_value=None,
        ):
            result = runner.invoke(app, [])

        assert result.exit_code == 1, result.output
        assert "GUI cannot be served" in result.output
        mock_run.assert_not_called()

    @patch("uvicorn.run")
    def test_api_only_starts_without_assets(self, mock_run, runner):
        """--api-only with no assets → starts in API-only mode (exit 0)."""
        from aptl.cli.web import app

        with patch(
            "aptl.cli.web.get_web_asset_root",
            return_value=None,
        ):
            result = runner.invoke(app, ["--api-only"])

        assert result.exit_code == 0, result.output
        assert "API-only mode" in result.output
        mock_run.assert_called_once()

    @patch("uvicorn.run")
    def test_web_root_sets_aptl_web_root_env(self, mock_run, runner, tmp_path):
        """Resolved --web-root is written to APTL_WEB_ROOT so the uvicorn worker sees it."""
        root = tmp_path / "dist"
        root.mkdir()
        (root / "index.html").write_text("SPA")

        from aptl.cli.web import app
        import os

        result = runner.invoke(app, ["--web-root", str(root)])

        assert result.exit_code == 0
        assert os.environ.get("APTL_WEB_ROOT") == str(root)
        # Cleanup
        os.environ.pop("APTL_WEB_ROOT", None)
