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
        # The summary contract is narrow: id/name/description only. The catalog
        # ``path`` locator is internal and must not leak into the card DTO.
        _write_catalog(
            tmp_path,
            [
                {
                    "id": "obs-core",
                    "name": "Observability Core",
                    "path": "scenarios/techvault-observability-core.sdl.yaml",
                    "description": "Smallest bounded startup surface.",
                }
            ],
        )

        response = api_client.get("/api/scenarios")

        assert response.status_code == 200
        entry = response.json()[0]
        assert set(entry.keys()) == {"id", "name", "description"}

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


class TestRemovedScenarioDetailRoute:
    """The scenario *detail* (workbench) route stays absent in this slice."""

    def test_detail_endpoint_is_absent(self, api_client):
        response = api_client.get("/api/scenarios/example")
        assert response.status_code == 404
