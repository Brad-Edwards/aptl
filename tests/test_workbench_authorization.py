"""Browser profiles are an authorization boundary, not a UI filter."""

from types import SimpleNamespace

from fastapi.testclient import TestClient


def test_browser_enforces_role_and_caller_on_every_action():
    from aptl.workbench.app import BrowserPrincipal, create_participant_workbench_app

    class Runtime:
        current_launch = None

        def switch(self, profile):
            self.current_launch = SimpleNamespace(
                profile=SimpleNamespace(value=profile), run_id="a" * 32
            )
            return self.current_launch

        def respond(self, message):
            return "allowed"

        def close(self):
            self.current_launch = None

    runtime = Runtime()
    alice = BrowserPrincipal(caller_id="alice", profiles=("red",))
    bob = BrowserPrincipal(caller_id="bob", profiles=("blue",))
    caller = [alice]
    client = TestClient(create_participant_workbench_app(runtime, lambda _: caller[0]))
    assert client.post("/workbench/profiles/blue").status_code == 403
    assert client.post("/workbench/profiles/red").status_code == 200
    caller[0] = bob
    assert (
        client.post("/workbench/messages", json={"message": "inspect"}).status_code
        == 403
    )
    assert client.delete("/workbench/profile").status_code == 403
    assert client.get("/workbench").status_code == 403
    caller[0] = True  # Boolean authentication cannot silently grant every role.
    assert client.post("/workbench/profiles/blue").status_code == 401


def test_local_workbench_renderer_uses_guest_dispatch_not_direct_node(tmp_path):
    import json
    from pathlib import Path

    from aptl.workbench.bootstrap import render_guest_workbench_config
    from aptl.workbench.guest_binding import GuestDispatchBinding
    from aptl.workbench.profiles import ProfileId
    from tests.test_mcp_access import access_record, grant

    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=access_record(),
        grants=(grant(),),
        project_dir=tmp_path,
        node_executable=Path("/usr/bin/node"),
        management_home=tmp_path,
        run_id="run_20260917T120000Z",
        delivery="rootful-integration",
    )
    binding_path = tmp_path / "binding.json"
    binding_path.write_text(binding.model_dump_json())
    binding_path.chmod(0o600)
    path = render_guest_workbench_config(
        binding_path=binding_path,
        grant_id="grant-1",
        profile=ProfileId.RED,
        run_id=binding.run_id,
        executable=Path("/usr/bin/aptl"),
        output=tmp_path / "configs",
    )
    document = json.loads(path.read_text())
    server = document["mcpServers"]["aptl-red"]
    assert server["command"] == "/usr/bin/aptl"
    assert server["args"][:2] == ["mcp-access", "dispatch"]
    assert server["env"] == {
        "SSH_ORIGINAL_COMMAND": "aptl-mcp-v1 instance-1 1 aptl-red"
    }
    assert "ANTHROPIC" not in path.read_text()
    import pytest

    with pytest.raises(ValueError):
        render_guest_workbench_config(
            binding_path=binding_path,
            grant_id="grant-1",
            profile=ProfileId.BLUE,
            run_id=binding.run_id,
            executable=Path("/usr/bin/aptl"),
            output=tmp_path / "other",
        )


def test_canonical_browser_ingress_rechecks_live_capture_and_grant(
    tmp_path, monkeypatch
):
    from pathlib import Path

    from aptl.core.scenario_bundle import env_pack_bundle
    from aptl.workbench import guest_binding
    from aptl.workbench.app import BrowserPrincipal
    from aptl.workbench.bootstrap import (
        ApplianceWorkbenchSettings,
        create_local_workbench_app,
    )
    from aptl.workbench.guest_binding import GuestDispatchBinding
    from tests.test_mcp_access import access_record, grant

    pack = env_pack_bundle(tmp_path / "pack")
    record = access_record(scenario_pack=pack.pack_identity)
    caller = grant()
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=record,
        grants=(caller,),
        project_dir=tmp_path,
        node_executable=Path("/usr/bin/node"),
        management_home=tmp_path,
        run_id="a" * 32,
        delivery="rootful-integration",
    )
    path = tmp_path / "binding.json"
    path.write_text(binding.model_dump_json())
    path.chmod(0o600)
    observation = dict(
        boot_id=record.guest_boot_id,
        daemon_id=record.guest_daemon_id,
        project=record.guest_project,
        containers=record.container_ids,
        run_id=binding.run_id,
        capture={"ready": True, "run_id": binding.run_id},
    )
    monkeypatch.setattr(guest_binding, "observe_guest", lambda _: observation)
    settings = ApplianceWorkbenchSettings(
        payload_root=tmp_path,
        state_dir=tmp_path / "state",
        claude_executable=Path("/usr/bin/false"),
        model="test",
    )
    app = create_local_workbench_app(
        settings,
        binding_path=path,
        grant_id=caller.grant_id,
        aptl_executable=Path("/usr/bin/false"),
        secret_source={},
        authorizer=lambda request: (
            BrowserPrincipal(caller.grant_id, ("red",))
            if request.headers.get("X-Seat") == "admitted"
            else None
        ),
    )
    client = TestClient(app)
    assert client.get("/").status_code == 401
    headers = {"X-Seat": "admitted"}
    assert client.get("/", headers=headers).status_code == 200
    assert client.get("/guide/", headers=headers).status_code == 200
    assert client.get("/api/lab/status", headers=headers).status_code == 404
    assert client.post("/workbench/profiles/blue", headers=headers).status_code == 403
    observation["capture"]["ready"] = False
    assert client.get("/", headers=headers).status_code == 401
    observation["capture"]["ready"] = True
    path.write_text(
        binding.model_copy(
            update={"grants": (caller.model_copy(update={"revoked": True}),)}
        ).model_dump_json()
    )
    assert client.get("/", headers=headers).status_code == 401
