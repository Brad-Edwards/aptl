"""Tests for scenario API projection from the configured acquired pack."""

import logging
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client(tmp_path):
    from aptl.api.deps import get_project_dir, verify_token
    from aptl.api.main import app
    from starlette.testclient import TestClient

    project_root = Path(__file__).resolve().parents[1]
    (tmp_path / "aptl.json").write_bytes((project_root / "aptl.json").read_bytes())
    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    app.dependency_overrides[verify_token] = lambda: None
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


def test_list_reports_validated_acquired_pack_identity(api_client):
    response = api_client.get("/api/scenarios")

    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body] == ["techvault"]
    assert body[0]["name"] == "TechVault"
    assert body[0]["pack"] == {
        "id": "techvault",
        "version": "0.1.0",
        "set_digest": "sha256:c532775575d99438f4b4890d49a4fdb7354921f0405afdaa9f370ea4fe3f5a20",
        "maturity": "built",
    }
    assert body[0]["validation"]["valid"] is True
    assert body[0]["required_containers"]
    assert ".aptl/staged-packs" not in response.text
    assert ".sdl.yaml" not in response.text


def test_detail_projects_same_validated_identity(api_client):
    response = api_client.get("/api/scenarios/techvault")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "techvault"
    assert body["pack"]["id"] == "techvault"
    assert body["pack"]["version"] == "0.1.0"
    assert body["pack"]["maturity"] == "built"
    assert body["blocks"][0]["type"] == "narrative"
    assert ".aptl/staged-packs" not in response.text


def test_detail_unknown_id_returns_404(api_client):
    response = api_client.get("/api/scenarios/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"detail": "Unknown scenario"}


def test_list_degrades_when_pack_is_rejected(api_client, mocker):
    mocker.patch(
        "aptl.api.routers.scenarios.load_scenario_catalog",
        side_effect=ValueError("digest mismatch"),
    )
    response = api_client.get("/api/scenarios")
    assert response.status_code == 200
    assert response.json() == []


def test_detail_rejected_pack_is_redacted(api_client, mocker):
    mocker.patch(
        "aptl.api.routers.scenarios.load_scenario_catalog",
        side_effect=ValueError("/private/staging/digest mismatch"),
    )
    response = api_client.get("/api/scenarios/techvault")
    assert response.status_code == 502
    assert "private" not in response.text


def test_detail_does_not_log_user_controlled_id(api_client, caplog):
    caplog.set_level(logging.INFO, logger="aptl.api.scenarios")
    response = api_client.get("/api/scenarios/%0Aforged-entry")
    assert response.status_code == 404
    assert "GET /scenarios/{scenario_id}" in caplog.text
    assert "forged-entry" not in caplog.text
