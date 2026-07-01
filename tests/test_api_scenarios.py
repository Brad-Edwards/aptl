"""Tests for the scenario catalog summary API endpoint (UI-008c)."""

import json

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client(tmp_path):
    """FastAPI test client with auth bypassed and project_dir -> tmp_path.

    The /api/{full_path:path} catch-all (added by the BFF refactor) requires
    authentication, so requests to truly absent routes return 404 only once
    verify_token is bypassed (otherwise unauthenticated clients get 401).
    """
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


def _write_catalog(project_dir, scenarios):
    catalog_dir = project_dir / "scenarios"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    (catalog_dir / "catalog.json").write_text(
        json.dumps({"version": 1, "scenarios": scenarios})
    )


_MINIMAL_SDL = """
name: minimal
description: A minimal ACES scenario.
nodes:
  the-net:
    type: switch
    description: switch node
  ssh-host:
    type: vm
    os: linux
    services:
      - {name: ssh, port: 22, protocol: tcp}
"""


def _write_scenario_file(project_dir, filename, body=_MINIMAL_SDL):
    scenarios_dir = project_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    (scenarios_dir / filename).write_text(body)


class TestScenarioListEndpoint:
    """GET /api/scenarios projects the curated catalog into card summaries."""

    def test_list_returns_catalog_projection(self, api_client, tmp_path):
        _write_catalog(
            tmp_path,
            [
                {
                    "id": "techvault-operational",
                    "name": "TechVault Operational",
                    "path": "scenarios/techvault-operational.sdl.yaml",
                    "description": "Default public APTL startup scenario.",
                },
                {
                    "id": "techvault-defensive-min",
                    "name": "TechVault Defensive Minimum",
                    "path": "scenarios/techvault-defensive-min.sdl.yaml",
                    "description": "Wazuh manager, indexer, and dashboard.",
                },
            ],
        )

        response = api_client.get("/api/scenarios")

        assert response.status_code == 200
        data = response.json()
        assert [s["id"] for s in data] == [
            "techvault-operational",
            "techvault-defensive-min",
        ]
        assert data[0]["name"] == "TechVault Operational"
        assert data[0]["description"] == "Default public APTL startup scenario."

    def test_list_omits_internal_path_field(self, api_client, tmp_path):
        # The summary is enriched (UI-008d) with card facts, but the internal
        # catalog ``path`` locator must never leak into the card DTO.
        _write_scenario_file(tmp_path, "obs-core.sdl.yaml")
        _write_catalog(
            tmp_path,
            [
                {
                    "id": "obs-core",
                    "name": "Observability Core",
                    "path": "scenarios/obs-core.sdl.yaml",
                    "description": "Smallest bounded startup surface.",
                    "metadata": {
                        "mode": "blue",
                        "difficulty": "beginner",
                        "estimated_minutes": 20,
                        "tags": ["observability"],
                    },
                }
            ],
        )

        response = api_client.get("/api/scenarios")

        assert response.status_code == 200
        entry = response.json()[0]
        assert "path" not in entry
        assert set(entry.keys()) == {
            "id",
            "name",
            "description",
            "mode",
            "difficulty",
            "estimated_minutes",
            "tags",
            "required_containers",
            "validation",
        }
        assert entry["mode"] == "blue"
        assert entry["required_containers"] == ["ssh-host"]
        assert entry["validation"]["valid"] is True

    def test_list_enriched_summary_degrades_when_sdl_missing(
        self, api_client, tmp_path
    ):
        # A catalog entry whose SDL cannot be parsed still lists (card renders
        # with an invalid validation state), and never 500s the page.
        _write_catalog(
            tmp_path,
            [
                {
                    "id": "broken",
                    "name": "Broken",
                    "path": "scenarios/does-not-exist.sdl.yaml",
                    "description": "Missing SDL.",
                }
            ],
        )

        response = api_client.get("/api/scenarios")

        assert response.status_code == 200
        entry = response.json()[0]
        assert entry["validation"]["valid"] is False
        assert entry["required_containers"] == []
        assert "does-not-exist" not in json.dumps(entry)


class TestScenarioDetailEndpoint:
    """GET /api/scenarios/{id} projects the ACES SDL into a workbench detail."""

    def _catalog_with_minimal(self, tmp_path):
        _write_scenario_file(tmp_path, "minimal.sdl.yaml")
        _write_catalog(
            tmp_path,
            [
                {
                    "id": "minimal",
                    "name": "Minimal Scenario",
                    "path": "scenarios/minimal.sdl.yaml",
                    "description": "A minimal scenario.",
                    "metadata": {"mode": "purple", "difficulty": "advanced"},
                }
            ],
        )

    def test_detail_returns_projection(self, api_client, tmp_path):
        self._catalog_with_minimal(tmp_path)

        response = api_client.get("/api/scenarios/minimal")

        assert response.status_code == 200
        body = response.json()
        # A real projection-path response shape the /api catch-all (which only
        # 404s) cannot produce — proves get_scenario_detail is actually wired.
        assert isinstance(body["blocks"], list)
        assert body["id"] == "minimal"
        assert body["name"] == "Minimal Scenario"
        assert body["mode"] == "purple"
        assert body["required_containers"] == ["ssh-host"]
        assert body["validation"]["valid"] is True
        assert body["blocks"][0]["type"] == "narrative"
        block_types = {b["type"] for b in body["blocks"]}
        assert "container-status" in block_types
        assert "terminal" in block_types

    def test_detail_unknown_id_returns_404(self, api_client, tmp_path):
        self._catalog_with_minimal(tmp_path)

        response = api_client.get("/api/scenarios/does-not-exist")

        assert response.status_code == 404

    def test_detail_no_catalog_returns_404(self, api_client):
        response = api_client.get("/api/scenarios/anything")
        assert response.status_code == 404

    def test_detail_omits_internal_path(self, api_client, tmp_path):
        self._catalog_with_minimal(tmp_path)

        response = api_client.get("/api/scenarios/minimal")

        assert response.status_code == 200
        assert "minimal.sdl.yaml" not in response.text

    def test_detail_invalid_sdl_is_redacted(self, api_client, tmp_path):
        _write_scenario_file(
            tmp_path, "bad.sdl.yaml", body="this: is: not: valid: sdl: ::\n"
        )
        _write_catalog(
            tmp_path,
            [
                {
                    "id": "bad",
                    "name": "Bad",
                    "path": "scenarios/bad.sdl.yaml",
                    "description": "Invalid SDL.",
                }
            ],
        )

        response = api_client.get("/api/scenarios/bad")

        assert response.status_code == 502
        # Redacted: no raw parser dump and no internal path locator.
        assert "bad.sdl.yaml" not in response.text
        assert "Traceback" not in response.text

    def test_list_empty_when_no_catalog(self, api_client):
        # A lab need not ship a curated catalog; Lab Home degrades to empty.
        response = api_client.get("/api/scenarios")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_empty_on_malformed_catalog(self, api_client, tmp_path):
        # A malformed catalog must not 500 the Lab Home page.
        catalog_dir = tmp_path / "scenarios"
        catalog_dir.mkdir(parents=True, exist_ok=True)
        (catalog_dir / "catalog.json").write_text("{not: valid: yaml: ::}")

        response = api_client.get("/api/scenarios")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_empty_on_schema_violation(self, api_client, tmp_path):
        # Wrong catalog version is a schema violation -> degrade, do not 500.
        catalog_dir = tmp_path / "scenarios"
        catalog_dir.mkdir(parents=True, exist_ok=True)
        (catalog_dir / "catalog.json").write_text(
            json.dumps({"version": 2, "scenarios": []})
        )

        response = api_client.get("/api/scenarios")
        assert response.status_code == 200
        assert response.json() == []
