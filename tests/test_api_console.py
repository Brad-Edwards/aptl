"""Tests for the console API router."""

import json

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client(tmp_path):
    from aptl.api.deps import get_project_dir
    from aptl.api.main import app
    from aptl.api.routers import console as console_router
    from starlette.testclient import TestClient

    # Each test gets a clean project dir; clear the per-project store cache so
    # state never bleeds between tests sharing the process.
    console_router._STORES.clear()
    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        console_router._STORES.clear()


class TestState:
    def test_empty_state(self, api_client):
        res = api_client.get("/api/console/state")
        assert res.status_code == 200
        data = res.json()
        assert data["sessions"] == []
        assert data["scratchpads"] == []
        assert data["provider"]["provider"] in ("echo", "anthropic")


class TestSessions:
    def test_create_and_list(self, api_client):
        res = api_client.post("/api/console/sessions", json={"role": "red"})
        assert res.status_code == 200
        sess = res.json()
        assert sess["role"] == "red"
        assert sess["title"] == "Red session"

        state = api_client.get("/api/console/state").json()
        assert len(state["sessions"]) == 1

    def test_update_session_mcp_allowlist(self, api_client):
        sess = api_client.post("/api/console/sessions", json={"role": "purple"}).json()
        res = api_client.patch(
            f"/api/console/sessions/{sess['id']}",
            json={"mcp_servers": ["kali-ssh"], "title": "custom"},
        )
        assert res.status_code == 200
        updated = res.json()
        assert updated["mcp_servers"] == ["kali-ssh"]
        assert updated["title"] == "custom"

    def test_delete_session(self, api_client):
        sess = api_client.post("/api/console/sessions", json={"role": "blue"}).json()
        assert api_client.delete(f"/api/console/sessions/{sess['id']}").status_code == 200
        assert api_client.get(f"/api/console/sessions/{sess['id']}").status_code == 404

    def test_get_missing_session_404(self, api_client):
        assert api_client.get("/api/console/sessions/nope").status_code == 404


class TestScratchpads:
    def test_create_attach_and_share(self, api_client):
        pad = api_client.post(
            "/api/console/scratchpads", json={"name": "shared", "content": "init"}
        ).json()
        red = api_client.post(
            "/api/console/sessions", json={"role": "red", "scratchpads": [pad["id"]]}
        ).json()
        blue = api_client.post(
            "/api/console/sessions", json={"role": "blue", "scratchpads": [pad["id"]]}
        ).json()
        assert pad["id"] in red["scratchpads"]
        assert pad["id"] in blue["scratchpads"]

    def test_duplicate_name_conflict(self, api_client):
        api_client.post("/api/console/scratchpads", json={"name": "dup"})
        res = api_client.post("/api/console/scratchpads", json={"name": "dup"})
        assert res.status_code == 409

    def test_update_and_delete(self, api_client):
        pad = api_client.post("/api/console/scratchpads", json={"name": "p"}).json()
        upd = api_client.patch(
            f"/api/console/scratchpads/{pad['id']}", json={"content": "new"}
        )
        assert upd.json()["content"] == "new"
        assert api_client.delete(f"/api/console/scratchpads/{pad['id']}").status_code == 200


class TestMessageStream:
    def test_empty_message_rejected(self, api_client):
        sess = api_client.post("/api/console/sessions", json={"role": "red"}).json()
        res = api_client.post(
            f"/api/console/sessions/{sess['id']}/messages", json={"content": "   "}
        )
        assert res.status_code == 422

    def test_stream_persists_turn(self, api_client):
        sess = api_client.post("/api/console/sessions", json={"role": "red"}).json()
        with api_client.stream(
            "POST",
            f"/api/console/sessions/{sess['id']}/messages",
            json={"content": "hello"},
        ) as res:
            assert res.status_code == 200
            body = "".join(res.iter_text())
        assert "user_message" in body
        assert "assistant_message" in body

        # The transcript was persisted.
        stored = api_client.get(f"/api/console/sessions/{sess['id']}").json()
        roles = [m["role"] for m in stored["messages"]]
        assert roles == ["user", "assistant"]

    def test_stream_runs_scratchpad_tool(self, api_client):
        pad = api_client.post(
            "/api/console/scratchpads", json={"name": "findings"}
        ).json()
        sess = api_client.post(
            "/api/console/sessions", json={"role": "red", "scratchpads": [pad["id"]]}
        ).json()
        cmd = '/run scratchpad_write {"name": "findings", "content": "owned"}'
        with api_client.stream(
            "POST",
            f"/api/console/sessions/{sess['id']}/messages",
            json={"content": cmd},
        ) as res:
            body = "".join(res.iter_text())
        assert "tool_result" in body
        pad_after = api_client.get("/api/console/state").json()["scratchpads"][0]
        assert pad_after["content"] == "owned"
