"""Tests for removed scenario API endpoints."""

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client():
    """Create a FastAPI test client."""
    from aptl.api.main import app
    from starlette.testclient import TestClient

    with TestClient(app) as client:
        yield client


class TestRemovedScenarioRoutes:
    """The legacy scenario API should not remain mounted."""

    def test_list_endpoint_is_absent(self, api_client):
        response = api_client.get("/api/scenarios")
        assert response.status_code == 404

    def test_detail_endpoint_is_absent(self, api_client):
        response = api_client.get("/api/scenarios/example")
        assert response.status_code == 404
