"""Shared test fixtures for APTL CLI tests."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for config files."""
    return tmp_path


@pytest.fixture
def valid_config_dict() -> dict:
    """A minimal valid APTL configuration dictionary."""
    return {
        "lab": {
            "name": "test-lab",
            "network_subnet": "172.20.0.0/16",
        },
        "containers": {
            "wazuh": True,
            "victim": True,
            "kali": True,
            "reverse": False,
        },
    }


@pytest.fixture
def valid_config_file(tmp_config_dir: Path, valid_config_dict: dict) -> Path:
    """Write a valid JSON config file and return its path."""
    config_path = tmp_config_dir / "aptl.json"
    config_path.write_text(json.dumps(valid_config_dict))
    return config_path


@pytest.fixture
def mock_subprocess(mocker):
    """Mock subprocess.run for commands that shell out."""
    return mocker.patch("subprocess.run")


@pytest.fixture
def mock_container() -> MagicMock:
    """A mock Docker container object."""
    container = MagicMock()
    container.name = "aptl-victim"
    container.status = "running"
    container.short_id = "abc123"
    container.attrs = {
        "State": {"Health": {"Status": "healthy"}},
        "NetworkSettings": {
            "Networks": {
                "aptl-network": {"IPAddress": "172.20.0.20"}
            }
        },
    }
    return container


@pytest.fixture
def mock_docker_client(mocker, mock_container):
    """Mock docker.from_env() returning a client with containers."""
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [mock_container]
    mock_client.containers.get.return_value = mock_container
    mocker.patch("aptl.core.lab.docker_client", return_value=mock_client)
    return mock_client
