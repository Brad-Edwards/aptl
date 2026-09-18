"""Per-generation appliance access channel and host publication tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import socket
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aptl.appliance.seat.access import (
    GuestAccessBundle,
    GuestAccessRequest,
    GuestRuntimeEvidence,
    SeatAccessEnrollment,
    configure_host_clients,
    encode_guest_access_bundle,
    invalidate_host_access,
    persist_host_access_bundle,
    publish_guest_access,
    publish_guest_access_request,
    read_guest_access_request,
    wait_for_guest_access,
)
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.workbench.dispatch import key_fingerprint
from tests.test_appliance_boundary_inventory import _binding, _guest, _host
from tests.test_mcp_access import access_record, grant


def _public_key() -> str:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )


def _request() -> GuestAccessRequest:
    binding = _binding()
    host = _host().model_copy(update={"observation_id": binding.host_observation_id})
    guest = _guest()
    guest_endpoint = BoundaryEndpoint(
        audience="host-mcp",
        address="127.0.0.1",
        port=2222,
        protocol="tcp",
        guest_address="127.0.0.1",
        guest_port=2222,
    )
    return GuestAccessRequest(
        schema_version="aptl.guest-access-request/v1",
        nonce="1" * 64,
        seat_id="seat-1",
        instance_id="a" * 32,
        generation=2,
        launch_descriptor_digest="sha256:" + "2" * 64,
        enrollment=SeatAccessEnrollment(
            owner_id="alice",
            grant_id="seat-1-red",
            public_key=_public_key(),
            profile="red",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        guest_endpoint=guest_endpoint,
        outer_endpoint=guest_endpoint.model_copy(
            update={"port": 30222, "guest_port": 2222}
        ),
        binding=binding,
        host_observation=host,
        guest_observation=guest,
    )


def _bundle(host_public_key: str) -> GuestAccessBundle:
    request = _request()
    identity = {
        "seat_id": request.seat_id,
        "instance_id": request.instance_id,
        "generation": request.generation,
    }
    record = access_record(
        **identity,
        host_key_fingerprint=key_fingerprint(host_public_key),
        guest_endpoint={"address": "127.0.0.1", "port": 2222},
        outer_endpoint={"address": "127.0.0.1", "port": 30222},
    )
    caller = grant(**identity, grant_id=request.enrollment.grant_id)
    return GuestAccessBundle(
        schema_version="aptl.guest-access-bundle/v1",
        nonce=request.nonce,
        **identity,
        access=record,
        grant=caller,
        host_public_key=host_public_key,
        runtime_evidence=GuestRuntimeEvidence(
            schema_version="aptl.guest-runtime-evidence/v1",
            run_id="run-1",
            run_record={
                "schema_version": "aptl.run-record/v1",
                "outcome": "success",
                "backend_evidence": {
                    "range_snapshot": {"containers": [], "networks": []}
                },
            },
            snapshot={"containers": [], "networks": []},
        ),
    )


def test_access_request_is_create_once_and_strict(tmp_path: Path) -> None:
    path = tmp_path / "access-request.json"
    request = _request()

    publish_guest_access_request(path, request)

    assert read_guest_access_request(path) == request
    assert path.stat().st_mode & 0o777 == 0o400
    try:
        publish_guest_access_request(path, request)
    except ValueError as exc:
        assert "could not be published" in str(exc)
    else:  # pragma: no cover - create-once is a security invariant
        raise AssertionError("request replacement was accepted")


def test_access_bundle_is_private_and_invalidated_on_stop(tmp_path: Path) -> None:
    bundle = _bundle(_public_key())
    output = persist_host_access_bundle(tmp_path, bundle)

    assert (output / "access.json").stat().st_mode & 0o777 == 0o600
    assert (output / "grant.json").exists()

    invalidate_host_access(tmp_path, reason="seat-stopped")

    assert not (output / "grant.json").exists()
    assert (output / "invalidated").read_text() == "seat-stopped\n"
    assert '"lifecycle_state":"needs-reset"' in (output / "access.json").read_text()


def test_bundle_configures_both_native_clients_without_provider_state(
    tmp_path: Path,
) -> None:
    host_key = _public_key()
    bundle = _bundle(host_key)
    identity = tmp_path / "transport-key"
    identity.write_text("private-key-placeholder")

    paths = configure_host_clients(
        bundle=bundle,
        project_dir=tmp_path,
        identity_file=identity,
        username="aptl-mcp",
        clients=("claude", "codex"),
    )

    assert {path.relative_to(tmp_path).as_posix() for path in paths} == {
        ".mcp.json",
        ".codex/config.toml",
    }
    content = "\n".join(path.read_text() for path in paths)
    assert "30222" in content
    assert "provider" not in content.lower()


def test_guest_access_channel_roundtrips_current_generation(tmp_path: Path) -> None:
    request = _request()
    bundle = _bundle(_public_key()).model_copy(
        update={
            "nonce": request.nonce,
            "seat_id": request.seat_id,
            "instance_id": request.instance_id,
            "generation": request.generation,
        }
    )
    payload = encode_guest_access_bundle(bundle)
    socket_path = tmp_path / "access.sock"
    listening = threading.Event()

    def publish() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(socket_path))
            server.listen(1)
            listening.set()
            connection, _ = server.accept()
            with connection:
                connection.sendall(payload[:31])
                connection.sendall(payload[31:])

    thread = threading.Thread(target=publish)
    thread.start()
    assert listening.wait(timeout=2)

    observed = wait_for_guest_access(
        socket_path,
        request,
        process_alive=lambda: True,
        timeout_seconds=2,
    )
    thread.join(timeout=2)

    assert observed == bundle
    assert not thread.is_alive()


def test_guest_can_publish_access_bundle_to_virtio_character_device() -> None:
    publish_guest_access(Path("/dev/null"), _bundle(_public_key()))


def test_guest_access_wait_fails_if_vm_exits_before_channel_exists(
    tmp_path: Path,
) -> None:
    with pytest.raises(Exception, match="VM exited before guest access"):
        wait_for_guest_access(
            tmp_path / "missing.sock",
            _request(),
            process_alive=lambda: False,
            timeout_seconds=0.1,
        )
