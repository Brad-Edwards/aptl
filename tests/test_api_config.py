"""Tests for config API endpoints."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client(tmp_path):
    """Create a FastAPI test client with DI override for project_dir."""
    from aptl.api.deps import get_project_dir, verify_token
    from aptl.api.main import app
    from starlette.testclient import TestClient

    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    app.dependency_overrides[verify_token] = lambda: None
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


class TestConfigEndpoint:
    def test_returns_config(self, api_client, tmp_path):
        config = {
            "lab": {"name": "test-lab", "network_subnet": "172.20.0.0/16"},
            "containers": {
                "wazuh": True,
                "victim": True,
                "kali": True,
                "reverse": False,
            },
        }
        (tmp_path / "aptl.json").write_text(json.dumps(config))

        response = api_client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        assert data["lab_name"] == "test-lab"
        assert data["network_subnet"] == "172.20.0.0/16"
        assert data["containers"]["wazuh"] is True
        assert data["containers"]["victim"] is True

    def test_returns_defaults_when_no_config(self, api_client):
        response = api_client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        assert data["lab_name"] == "aptl"
        assert data["run_storage_backend"] == "local"

    def test_dynamic_container_list(self, api_client):
        """Config endpoint returns all ContainerSettings fields dynamically."""
        from aptl.core.config import ContainerSettings

        response = api_client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        # Every field in ContainerSettings should appear in the response
        for field_name in ContainerSettings.model_fields:
            assert field_name in data["containers"], f"Missing container: {field_name}"


class TestWebServeInfo:
    """The non-secret web-serve projection (UI-008f)."""

    def test_reports_build_version(self, api_client):
        from aptl import __version__

        data = api_client.get("/api/config").json()

        assert data["web"]["build_version"] == __version__

    def test_allowed_hosts_includes_loopback_defaults(self, api_client):
        data = api_client.get("/api/config").json()

        hosts = data["web"]["allowed_hosts"]
        assert "127.0.0.1" in hosts
        assert "localhost" in hosts

    def test_allowed_hosts_reflects_env(self, api_client):
        # Keep "testserver" so the TestClient Host still passes the BFF gate
        # (conftest sets it); add an extra host and assert it is projected.
        with patch.dict(
            os.environ, {"APTL_ALLOWED_HOSTS": "testserver,box.example.ts.net"}
        ):
            data = api_client.get("/api/config").json()

        assert "box.example.ts.net" in data["web"]["allowed_hosts"]
        # Loopback defaults are still present alongside the extra host.
        assert "127.0.0.1" in data["web"]["allowed_hosts"]

    def test_public_origin_from_env_trims_trailing_slash(self, api_client):
        with patch.dict(
            os.environ, {"APTL_WEB_PUBLIC_ORIGIN": "https://box.example.ts.net/"}
        ):
            data = api_client.get("/api/config").json()

        assert data["web"]["public_origin"] == "https://box.example.ts.net"

    def test_public_origin_null_when_unset(self, api_client):
        # Don't clear the whole env (conftest's APTL_ALLOWED_HOSTS must survive so
        # the Host gate still admits the TestClient); just ensure the origin is
        # unset. patch.dict restores the popped key on exit.
        with patch.dict(os.environ, {}):
            os.environ.pop("APTL_WEB_PUBLIC_ORIGIN", None)
            data = api_client.get("/api/config").json()

        assert data["web"]["public_origin"] is None

    def test_deployment_provider_reflects_config(self, api_client, tmp_path):
        config = {
            "lab": {"name": "test-lab"},
            "deployment": {"provider": "ssh-compose", "ssh_host": "10.0.0.5"},
        }
        (tmp_path / "aptl.json").write_text(json.dumps(config))

        data = api_client.get("/api/config").json()

        assert data["web"]["deployment_provider"] == "ssh-compose"

    def test_response_never_contains_the_api_token(self, api_client):
        """The projection must not leak any secret, e.g. an SSH host or token."""
        token = "s3cr3t-token-value-should-never-appear"
        with patch.dict(os.environ, {"APTL_API_TOKEN": token}):
            body = api_client.get("/api/config").text

        assert token not in body
        # The web sub-object exposes no secret-bearing keys.
        web = api_client.get("/api/config").json()["web"]
        assert set(web.keys()) == {
            "build_version",
            "allowed_hosts",
            "public_origin",
            "deployment_provider",
        }


class TestGetProjectDir:
    """Test the get_project_dir dependency directly."""

    def test_returns_env_var_when_set(self, tmp_path):
        from aptl.api.deps import get_project_dir

        with patch.dict(os.environ, {"APTL_PROJECT_DIR": str(tmp_path)}):
            result = get_project_dir()
            assert result == tmp_path

    def test_returns_cwd_when_env_not_set(self):
        from aptl.api.deps import get_project_dir

        with patch.dict(os.environ, {}, clear=True):
            # Remove APTL_PROJECT_DIR if present
            os.environ.pop("APTL_PROJECT_DIR", None)
            result = get_project_dir()
            assert result == Path.cwd()

    def test_raises_503_for_nonexistent_dir(self):
        from aptl.api.deps import get_project_dir
        from fastapi import HTTPException

        with patch.dict(os.environ, {"APTL_PROJECT_DIR": "/no/such/path"}):
            with pytest.raises(HTTPException) as exc_info:
                get_project_dir()
            assert exc_info.value.status_code == 503
