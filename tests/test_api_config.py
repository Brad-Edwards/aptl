"""Tests for config API endpoints."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client():
    """Create a FastAPI test client."""
    from aptl.api.main import app
    from starlette.testclient import TestClient

    return TestClient(app)


class TestConfigEndpoint:
    @patch("aptl.api.routers.config.get_project_dir")
    def test_returns_config(self, mock_dir, api_client, tmp_path):
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
        mock_dir.return_value = tmp_path

        response = api_client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        assert data["lab_name"] == "test-lab"
        assert data["network_subnet"] == "172.20.0.0/16"
        assert data["containers"]["wazuh"] is True
        assert data["containers"]["victim"] is True

    @patch("aptl.api.routers.config.get_project_dir")
    def test_returns_defaults_when_no_config(self, mock_dir, api_client, tmp_path):
        mock_dir.return_value = tmp_path

        response = api_client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        assert data["lab_name"] == "aptl"
        assert data["run_storage_backend"] == "local"


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
