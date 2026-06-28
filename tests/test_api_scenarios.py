"""Tests for removed scenario API endpoints."""

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client():
    """Create a FastAPI test client with auth bypassed.

    The /api/{full_path:path} catch-all (added by the BFF refactor) requires
    authentication, so requests to truly absent routes now return 401 for
    unauthenticated clients.  Bypass verify_token here so the test confirms
    that the paths return 404 (route not registered), not 401 (no auth).
    """
    from aptl.api.deps import verify_token
    from aptl.api.main import app
    from starlette.testclient import TestClient

    app.dependency_overrides[verify_token] = lambda: None
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


class TestRemovedScenarioRoutes:
    """The legacy scenario API should not remain mounted."""

    def test_list_endpoint_is_absent(self, api_client):
        response = api_client.get("/api/scenarios")
        assert response.status_code == 404

    def test_detail_endpoint_is_absent(self, api_client):
        response = api_client.get("/api/scenarios/example")
        assert response.status_code == 404
