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
    from aptl.api.deps import get_project_dir
    from aptl.api.main import app
    from starlette.testclient import TestClient

    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    client = TestClient(app)
    yield client
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
