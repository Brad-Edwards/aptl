"""Tests for scenario API endpoints."""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml


@pytest.fixture
def api_client():
    """Create a FastAPI test client."""
    from aptl.api.main import app
    from starlette.testclient import TestClient

    return TestClient(app)


@pytest.fixture
def scenarios_dir(tmp_path):
    """Create a temp scenarios directory with test scenarios."""
    sdir = tmp_path / "scenarios"
    sdir.mkdir()

    scenario1 = {
        "metadata": {
            "id": "recon-nmap",
            "name": "Nmap Recon",
            "description": "Network reconnaissance with nmap",
            "difficulty": "beginner",
            "estimated_minutes": 15,
            "tags": ["recon", "nmap"],
        },
        "mode": "red",
        "containers": {"required": ["kali", "victim"]},
        "objectives": {
            "red": [
                {
                    "id": "scan-target",
                    "description": "Scan the target",
                    "type": "manual",
                    "points": 100,
                }
            ],
            "blue": [],
        },
    }
    (sdir / "recon-nmap.yaml").write_text(yaml.dump(scenario1))

    scenario2 = {
        "metadata": {
            "id": "brute-force",
            "name": "Brute Force",
            "description": "SSH brute force detection",
            "difficulty": "intermediate",
            "estimated_minutes": 30,
            "tags": ["ssh", "detection"],
        },
        "mode": "blue",
        "containers": {"required": ["kali", "victim", "wazuh"]},
        "objectives": {
            "red": [],
            "blue": [
                {
                    "id": "detect-brute",
                    "description": "Detect brute force",
                    "type": "manual",
                    "points": 200,
                }
            ],
        },
    }
    (sdir / "brute-force.yaml").write_text(yaml.dump(scenario2))

    return sdir


class TestListScenarios:
    @patch("aptl.api.routers.scenarios.get_project_dir")
    def test_returns_all_scenarios(self, mock_dir, api_client, scenarios_dir):
        mock_dir.return_value = scenarios_dir.parent

        response = api_client.get("/api/scenarios")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        ids = {s["id"] for s in data}
        assert "recon-nmap" in ids
        assert "brute-force" in ids

    @patch("aptl.api.routers.scenarios.get_project_dir")
    def test_returns_scenario_details(self, mock_dir, api_client, scenarios_dir):
        mock_dir.return_value = scenarios_dir.parent

        response = api_client.get("/api/scenarios")

        data = response.json()
        nmap = next(s for s in data if s["id"] == "recon-nmap")
        assert nmap["name"] == "Nmap Recon"
        assert nmap["difficulty"] == "beginner"
        assert nmap["mode"] == "red"
        assert nmap["estimated_minutes"] == 15
        assert "kali" in nmap["containers_required"]

    @patch("aptl.api.routers.scenarios.get_project_dir")
    def test_returns_empty_list_when_no_scenarios(self, mock_dir, api_client, tmp_path):
        mock_dir.return_value = tmp_path

        response = api_client.get("/api/scenarios")

        assert response.status_code == 200
        assert response.json() == []


class TestGetScenario:
    @patch("aptl.api.routers.scenarios.get_project_dir")
    def test_returns_full_scenario(self, mock_dir, api_client, scenarios_dir):
        mock_dir.return_value = scenarios_dir.parent

        response = api_client.get("/api/scenarios/recon-nmap")

        assert response.status_code == 200
        data = response.json()
        assert data["metadata"]["id"] == "recon-nmap"
        assert data["mode"] == "red"

    @patch("aptl.api.routers.scenarios.get_project_dir")
    def test_returns_404_for_unknown(self, mock_dir, api_client, scenarios_dir):
        mock_dir.return_value = scenarios_dir.parent

        response = api_client.get("/api/scenarios/nonexistent")

        assert response.status_code == 404
