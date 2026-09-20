"""Guest enrollment and launch use injected observations without a Docker daemon."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aptl.core.config import AptlConfig
from aptl.workbench import guest_binding, preparation
from aptl.workbench.dispatch import DispatchSelector
from aptl.workbench.guest_binding import GuestAdmission, GuestDispatchBinding
from tests.test_mcp_access import access_record, grant


def _observation(record, run_id):
    return dict(
        boot_id=record.guest_boot_id,
        daemon_id=record.guest_daemon_id,
        project=record.guest_project,
        containers=record.container_ids,
        run_id=run_id,
        capture=dict(ready=True, run_id=run_id),
    )


def test_guest_enrollment_publishes_private_forced_keys_and_rejects_bad_inventory(
    tmp_path, monkeypatch
):
    record = access_record(container_ids={"aptl-kali": "a" * 64})
    original_read_text = Path.read_text

    def read_text(path, *args, **kwargs):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return record.guest_boot_id
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    run_id = "c" * 32
    public = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )
    host_public = tmp_path / "host.pub"
    host_public.write_text(public)
    backend = SimpleNamespace(
        project_name=record.guest_project,
        _docker_daemon_id=record.guest_daemon_id,
        bind_local_docker_socket=lambda: SimpleNamespace(success=True),
    )
    # This seam cannot reach a daemon, including the host's default Docker socket.
    monkeypatch.setattr(preparation, "DockerComposeBackend", lambda *a, **k: backend)
    monkeypatch.setattr(preparation, "load_config", lambda _: AptlConfig())
    monkeypatch.setattr(
        preparation, "observe_guest_containers", lambda _: record.container_ids
    )
    monkeypatch.setattr(
        preparation,
        "env_pack_bundle",
        lambda _: SimpleNamespace(pack_identity=record.scenario_pack),
    )
    monkeypatch.setattr(
        preparation,
        "expected_bundle_matrix",
        lambda *a: SimpleNamespace(service_aliases={"kali": ("aptl-kali",)}),
    )
    monkeypatch.setattr(
        preparation,
        "load_active_transcript_authorities",
        lambda _: [{"run_id": run_id}],
    )
    monkeypatch.setattr(
        preparation,
        "observe_guest",
        lambda binding: _observation(binding.access, run_id),
    )
    request = preparation.TransportPreparation(
        owner_id=record.owner_id,
        seat_id=record.seat_id,
        instance_id=record.instance_id,
        generation=record.generation,
        guest_endpoint=record.guest_endpoint,
        outer_endpoint=record.outer_endpoint,
        project_dir=tmp_path,
        management_home=tmp_path,
        docker_socket=tmp_path / "unused.sock",
        node_executable=Path("/usr/bin/node"),
        aptl_executable=Path("/usr/bin/aptl"),
        host_key=tmp_path / "host",
        host_public_key=host_public,
        username="participant",
        keys=(
            preparation.EnrolledKey(
                grant_id="caller",
                public_key=public,
                profile="red",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            ),
        ),
        delivery="rootful-integration",
    )
    output = tmp_path / "transport"
    binding = preparation.prepare_guest_transport(request, output)
    assert binding.run_id == run_id
    assert binding.access.container_ids == record.container_ids
    assert "restrict,command=" in (output / "authorized_keys").read_text()
    assert "ForceCommand" not in (output / "sshd_config").read_text()
    assert "AllowTcpForwarding no" in (output / "sshd_config").read_text()
    for path in output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads((output / "caller.grant.json").read_text())["revoked"] is False
    monkeypatch.setattr(preparation, "observe_guest_containers", lambda _: {})
    with pytest.raises(ValueError, match="inventory"):
        preparation.prepare_guest_transport(request, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_guest_launch_binds_native_kali_and_keeps_provider_auth_out(
    tmp_path, monkeypatch
):
    record = access_record(container_ids={"aptl-kali": "a" * 64})
    caller = grant()
    executable = tmp_path / "node"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=record,
        grants=(caller,),
        project_dir=tmp_path,
        node_executable=executable,
        management_home=tmp_path,
        docker_socket=tmp_path / "unused.sock",
        run_id="c" * 32,
        delivery="rootful-integration",
    )
    path = tmp_path / "binding.json"
    path.write_text(binding.model_dump_json())
    path.chmod(0o600)
    monkeypatch.setattr(
        guest_binding, "observe_guest", lambda _: _observation(record, binding.run_id)
    )
    selector = DispatchSelector(record.instance_id, record.generation, "aptl-red")
    admission = GuestAdmission(
        path, caller.grant_id, caller.public_key_fingerprint, selector
    )
    artifact = tmp_path / admission.server.artifact_ref
    artifact.parent.mkdir(parents=True)
    artifact.write_text("// fixture MCP artifact\n")
    values = {
        alias: "fixture-value-for-" + alias
        for alias in admission.server.credential_aliases
    }
    values.update(APTL_TEST_PORT="2222", ANTHROPIC_API_KEY="provider-must-not-cross")
    config_path = tmp_path / ".mcp.json"
    config_path.write_text(json.dumps({"mcpServers": {"aptl-red": {"env": values}}}))
    config_path.chmod(0o600)
    (tmp_path / "aptl.json").write_text(
        '{"run_storage":{"local_path":"./custom-runs"}}'
    )
    monkeypatch.setattr(
        "aptl.core.lab._server_config_port_refs", lambda *a: ("APTL_TEST_PORT",)
    )
    monkeypatch.setattr(guest_binding, "load_config", lambda _: AptlConfig())
    backend = SimpleNamespace(
        bind_local_docker_socket=lambda: SimpleNamespace(success=True),
        _docker_socket_path=tmp_path / "unused.sock",
        container_inspect=lambda _: {"fixture": True},
    )
    monkeypatch.setattr(guest_binding, "DockerComposeBackend", lambda *a, **k: backend)
    calls = []

    def ingress(inspected, expected):
        calls.append((inspected, expected))
        return {"APTL_MCP_KALI_HOST": "192.0.2.44"}

    monkeypatch.setattr("aptl.core.mcp_ingress.native_kali_ingress", ingress)
    argv, cwd, environment = admission.launch()
    assert argv == (str(executable), str(artifact))
    assert cwd == tmp_path
    assert environment["APTL_MCP_KALI_HOST"] == "192.0.2.44"
    assert environment["DOCKER_HOST"] == "unix://" + str(tmp_path / "unused.sock")
    assert environment["APTL_MCP_ADMITTED_RUN_ID"] == binding.run_id
    assert environment["APTL_MCP_RUN_STORE_BASE"] == str(tmp_path / "custom-runs")
    assert environment["APTL_TEST_PORT"] == "2222"
    assert "ANTHROPIC_API_KEY" not in environment
    assert calls == [({"fixture": True}, record.container_ids["aptl-kali"])]
    config_path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        admission.launch()
