"""Runtime admission rejects a changed daemon, workload or capture authority."""

import sys
from pathlib import Path

import pytest

from aptl.workbench.guest_binding import verify_guest_observation
from tests.test_mcp_access import access_record


def test_guest_inventory_uses_workspace_receipts_and_semantic_names(
    tmp_path, monkeypatch
):
    from aptl.core.deployment._compose_resource_ownership import (
        OwnershipConflictError,
        ResourceReceipt,
    )
    from aptl.core.deployment.docker_compose import DockerComposeBackend
    from aptl.workbench.guest_binding import observe_guest_containers

    backend = DockerComposeBackend(
        tmp_path, "aptl", docker_socket_path=tmp_path / "unused.sock"
    )
    backend._docker_daemon_id = "daemon-test"
    ownership = backend._ensure_resource_ownership()
    native_id = "a" * 64
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=native_id,
            external_name=ownership.container_name("aptl-kali"),
            semantic_name="aptl-kali",
            node_address="provision.node.kali",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-test",
            attempt_id="run-test",
        )
    )
    info = {
        "Id": native_id,
        "Name": "/" + ownership.container_name("aptl-kali"),
        "State": {"Running": True},
        "Config": {"Labels": ownership.labels(attempt_id="run-test")},
    }
    monkeypatch.setattr(
        backend,
        "host_list_lab_containers",
        lambda: [
            {
                "id": native_id,
                "name": ownership.container_name("aptl-kali"),
                "state": "running",
            }
        ],
    )
    monkeypatch.setattr(backend, "_raw_container_inspect", lambda _: info)
    assert backend.project_name != "aptl"
    assert observe_guest_containers(backend) == {"aptl-kali": native_id}
    info["Config"]["Labels"]["aptl.workspace.id"] = "foreign-workspace"
    with pytest.raises(OwnershipConflictError):
        observe_guest_containers(backend)


@pytest.mark.skipif(sys.platform != "linux", reason="guest admission runs on Linux")
def test_two_server_admissions_share_observation_lock(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from aptl.core.lifecycle_guard import LifecycleBusyError, lifecycle_mutation_lock
    from aptl.workbench import guest_binding
    from aptl.workbench.dispatch import DispatchSelector
    from aptl.workbench.guest_binding import GuestAdmission, GuestDispatchBinding
    from tests.test_mcp_access import grant

    caller = grant(profile="blue")
    record = access_record()
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=record,
        grants=(caller,),
        project_dir=tmp_path,
        node_executable=Path("/usr/bin/node"),
        management_home=tmp_path,
        run_id="c" * 32,
        delivery="rootful-integration",
    )
    path = tmp_path / "binding.json"
    path.write_text(binding.model_dump_json())
    path.chmod(0o600)
    overlap = threading.Barrier(3)
    release = threading.Event()

    def observe(_):
        overlap.wait(timeout=5)
        assert release.wait(timeout=5)
        return dict(
            boot_id=record.guest_boot_id,
            daemon_id=record.guest_daemon_id,
            project=record.guest_project,
            containers=record.container_ids,
            run_id=binding.run_id,
            capture={"run_id": binding.run_id, "ready": True},
        )

    # Keep the production observe_guest and real OS lifecycle locking. Only
    # replace Docker acquisition inside the locked observation.
    monkeypatch.setattr(guest_binding, "_observe_stable_guest", observe)

    def admit(server):
        with GuestAdmission(
            path,
            caller.grant_id,
            caller.public_key_fingerprint,
            DispatchSelector("instance-1", 1, server),
        ):
            return server

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(admit, server) for server in ("aptl-indexer", "aptl-wazuh")
        ]
        try:
            overlap.wait(timeout=5)
            with pytest.raises(LifecycleBusyError):
                with lifecycle_mutation_lock(tmp_path):
                    pass
        finally:
            release.set()
        assert {future.result() for future in futures} == {"aptl-indexer", "aptl-wazuh"}
    with lifecycle_mutation_lock(tmp_path):
        pass


def test_verified_discovery_does_not_replace_live_guest_identity():
    record = access_record()
    expected = dict(
        boot_id="boot-1",
        daemon_id="daemon-1",
        project="aptl-seat-1",
        containers={"kali": "a" * 64},
        run_id="c" * 32,
        capture={"run_id": "c" * 32, "ready": True},
    )
    verify_guest_observation(record, expected, run_id="c" * 32)
    for changes in (
        {"daemon_id": "other"},
        {"boot_id": "other"},
        {"project": "other"},
        {"containers": {"kali": "b" * 64}},
        {"capture": {"ready": False}},
        {"run_id": "d" * 32},
    ):
        with pytest.raises(ValueError):
            verify_guest_observation(record, {**expected, **changes}, run_id="c" * 32)


def test_live_grant_rotation_and_cleanup_failure_block_reentry(tmp_path, monkeypatch):
    from aptl.workbench import guest_binding
    from aptl.workbench.dispatch import DispatchSelector
    from aptl.workbench.guest_binding import GuestAdmission, GuestDispatchBinding
    from tests.test_mcp_access import grant

    record = access_record()
    caller = grant()
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=record,
        grants=(caller,),
        project_dir=tmp_path,
        node_executable=Path("/usr/bin/node"),
        management_home=tmp_path,
        run_id="c" * 32,
        delivery="rootful-integration",
    )
    path = tmp_path / "binding.json"
    path.write_text(binding.model_dump_json())
    path.chmod(0o600)
    monkeypatch.setattr(
        guest_binding,
        "observe_guest",
        lambda _: dict(
            boot_id=record.guest_boot_id,
            daemon_id=record.guest_daemon_id,
            project=record.guest_project,
            containers=record.container_ids,
            run_id="c" * 32,
            capture={"run_id": "c" * 32, "ready": True},
        ),
    )
    selector = DispatchSelector("instance-1", 1, "aptl-red")
    with GuestAdmission(
        path, caller.grant_id, caller.public_key_fingerprint, selector
    ) as admitted:
        admitted.authorize()
        rotated = caller.model_copy(
            update={"public_key_fingerprint": "SHA256:" + "C" * 43}
        )
        path.write_text(
            binding.model_copy(update={"grants": (rotated,)}).model_dump_json()
        )
        with pytest.raises(ValueError):
            admitted.authorize()
        admitted.cleanup(False)
    path.write_text(binding.model_dump_json())
    with pytest.raises(ValueError, match="cleanup"):
        with GuestAdmission(
            path, caller.grant_id, caller.public_key_fingerprint, selector
        ):
            pass


def test_guest_endpoint_binding_uses_management_path_not_ambient_host(
    monkeypatch, tmp_path
):
    from aptl.core.deployment.docker_compose import DockerComposeBackend

    monkeypatch.setenv("DOCKER_HOST", "unix:///wrong.sock")
    socket = tmp_path / "guest.sock"
    backend = DockerComposeBackend(tmp_path, docker_socket_path=socket)
    assert backend._resolve_binding_endpoint() is None
    assert backend._docker_socket_host == "unix://" + str(socket)


def test_transport_does_not_admit_a_start_or_reset_in_progress(tmp_path, monkeypatch):
    import threading
    from types import SimpleNamespace

    from aptl.core.lifecycle_guard import LifecycleBusyError, lifecycle_mutation_lock
    from aptl.workbench.guest_binding import observe_guest

    entered, release = threading.Event(), threading.Event()

    def lifecycle():
        with lifecycle_mutation_lock(tmp_path):
            entered.set()
            release.wait(5)

    worker = threading.Thread(target=lifecycle)
    worker.start()
    assert entered.wait(2)
    try:
        prepared_input_1 = SimpleNamespace(project_dir=tmp_path)
        with pytest.raises(LifecycleBusyError):
            observe_guest(prepared_input_1)
    finally:
        release.set()
        worker.join(2)


def test_revocation_is_checked_while_runtime_observation_is_blocked(
    tmp_path, monkeypatch
):
    import threading
    from pathlib import Path

    from aptl.workbench import guest_binding
    from aptl.workbench.dispatch import DispatchSelector
    from aptl.workbench.guest_binding import GuestAdmission, GuestDispatchBinding
    from tests.test_mcp_access import access_record, grant

    caller = grant()
    record = access_record()
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=record,
        grants=(caller,),
        project_dir=tmp_path,
        node_executable=Path("/usr/bin/node"),
        management_home=tmp_path,
        run_id="c" * 32,
        delivery="rootful-integration",
    )
    path = tmp_path / "binding.json"
    path.write_text(binding.model_dump_json())
    path.chmod(0o600)
    entered, release = threading.Event(), threading.Event()

    def observe(_):
        entered.set()
        release.wait(3)
        return {}

    monkeypatch.setattr(guest_binding, "observe_guest", observe)
    admitted = GuestAdmission(
        path,
        caller.grant_id,
        caller.public_key_fingerprint,
        DispatchSelector("instance-1", 1, "aptl-red"),
    )
    errors = []

    def check():
        try:
            admitted.authorize()
        except ValueError as exc:
            errors.append(exc)

    worker = threading.Thread(target=check)
    worker.start()
    assert entered.wait(2)
    try:
        path.write_text(
            binding.model_copy(
                update={"grants": (caller.model_copy(update={"revoked": True}),)}
            ).model_dump_json()
        )
        with pytest.raises(ValueError, match="authorized"):
            admitted.check_revocation()
    finally:
        release.set()
        worker.join(2)
    assert errors
