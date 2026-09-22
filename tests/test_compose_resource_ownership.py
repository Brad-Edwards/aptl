"""Workspace-scoped native-resource ownership for Compose backends (issue #964)."""

from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from threading import Event
from unittest.mock import MagicMock

import pytest
import yaml

from aptl.core.deployment._compose_owner_labels import complete_owner_labels
from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    ResourceReceipt,
    WorkspaceOwnership,
    write_compose_ownership_override,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import DeploymentNetworkRealization
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import DeploymentSpawnImageRequirement


_ID_A = "a" * 64
_ID_B = "b" * 64


def test_workspace_identity_is_stable_and_scopes_backend_names(tmp_path: Path) -> None:
    first = WorkspaceOwnership.ensure(tmp_path, "aptl")
    again = WorkspaceOwnership.ensure(tmp_path, "aptl")
    other = WorkspaceOwnership.ensure(tmp_path / "other", "aptl")

    assert again == first
    assert first.workspace_id != other.workspace_id
    assert first.project_name != other.project_name
    assert first.project_name.startswith("aptl-w")
    assert len(first.project_name) <= 63
    assert first.container_name("aptl-victim") != other.container_name("aptl-victim")
    assert first.container_name("aptl-victim").endswith("-victim")


def test_compose_receipt_requires_the_full_owner_label_tuple(tmp_path: Path) -> None:
    ownership = WorkspaceOwnership.ensure(tmp_path, "aptl")
    labels = {
        **ownership.labels(attempt_id="run-a"),
        "com.docker.compose.project": ownership.project_name,
        "com.docker.compose.service": "victim",
    }

    assert complete_owner_labels(
        ownership,
        labels,
        attempt_id="run-a",
        compose_kind="service",
        semantic_name="victim",
    )
    for key in labels:
        incomplete = {**labels, key: "foreign"}
        assert not complete_owner_labels(
            ownership,
            incomplete,
            attempt_id="run-a",
            compose_kind="service",
            semantic_name="victim",
        )


def test_workspace_identity_rejects_corrupt_or_symlinked_state(tmp_path: Path) -> None:
    state = tmp_path / ".aptl" / "lifecycle" / "workspace-ownership-v1.json"
    state.parent.mkdir(parents=True)
    state.write_text("not-json", encoding="utf-8")

    with pytest.raises(OwnershipConflictError, match="workspace ownership state"):
        WorkspaceOwnership.ensure(tmp_path, "aptl")

    state.unlink()
    target = tmp_path / "foreign"
    target.write_text("{}", encoding="utf-8")
    state.symlink_to(target)
    with pytest.raises(OwnershipConflictError, match="workspace ownership state"):
        WorkspaceOwnership.ensure(tmp_path, "aptl")


def test_receipts_are_immutable_and_bound_to_daemon_and_attempt(tmp_path: Path) -> None:
    ownership = WorkspaceOwnership.ensure(tmp_path, "aptl")
    receipt = ResourceReceipt(
        kind="container",
        native_id=_ID_A,
        external_name=ownership.container_name("aptl-victim"),
        semantic_name="aptl-victim",
        node_address="provision.node.victim",
        workspace_id=ownership.workspace_id,
        project_name=ownership.project_name,
        daemon_id="daemon-a",
        attempt_id="run-a",
    )

    ownership.record(receipt)
    ownership.record(receipt)
    loaded = ownership.receipts("container")

    assert loaded == (receipt,)
    conflicting = ResourceReceipt(**{**receipt.__dict__, "attempt_id": "run-b"})
    with pytest.raises(OwnershipConflictError, match="immutable ownership receipt"):
        ownership.record(conflicting)
    with pytest.raises(OwnershipConflictError, match="daemon identity"):
        ownership.candidates("aptl-victim", kind="container", daemon_id="daemon-b")


def test_receipt_inventory_ignores_only_in_progress_atomic_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent reader never mistakes the publisher's temp inode for a receipt."""

    from aptl.utils import pathsafe

    ownership = WorkspaceOwnership.ensure(tmp_path, "aptl")
    receipt = ResourceReceipt(
        kind="container",
        native_id=_ID_A,
        external_name=ownership.container_name("worker"),
        semantic_name="worker",
        node_address="provision.node.worker",
        workspace_id=ownership.workspace_id,
        project_name=ownership.project_name,
        daemon_id="daemon-a",
        attempt_id="run-a",
    )
    staged, release = Event(), Event()
    original_write_all = pathsafe.write_all

    def pause_while_temp_inode_is_visible(fd, data):
        staged.set()
        assert release.wait(timeout=5)
        original_write_all(fd, data)

    monkeypatch.setattr(pathsafe, "write_all", pause_while_temp_inode_is_visible)
    with ThreadPoolExecutor(max_workers=1) as pool:
        publication = pool.submit(ownership.record, receipt)
        try:
            assert staged.wait(timeout=5)
            receipt_dir = tmp_path / ".aptl/lifecycle/resource-receipts-v1/container"
            staged_names = [path.name for path in receipt_dir.iterdir()]
            assert len(staged_names) == 1
            assert staged_names[0].endswith(".tmp")
            assert ownership.receipts("container") == ()
            assert (
                ownership.candidates("worker", kind="container", daemon_id="daemon-a")
                == ()
            )
        finally:
            release.set()
        publication.result(timeout=5)

    assert ownership.receipts("container") == (receipt,)
    unexpected = receipt_dir / ".unexpected.tmp"
    unexpected.write_text("foreign", encoding="utf-8")
    with pytest.raises(OwnershipConflictError, match="inventory is malformed"):
        ownership.receipts("container")
    unexpected.unlink()
    (receipt_dir / "not-a-receipt.json").write_text("{}", encoding="utf-8")
    with pytest.raises(OwnershipConflictError, match="inventory is malformed"):
        ownership.receipts("container")


def test_receipt_publish_temp_name_remains_ascii_only() -> None:
    """Unicode numerals must not be mistaken for publisher-owned temp files."""

    from aptl.core.deployment._compose_resource_ownership import (
        _RECEIPT_PUBLISH_TEMP,
    )

    prefix = "." + "a" * 64 + ".json."
    assert _RECEIPT_PUBLISH_TEMP.fullmatch(prefix + "123.4.tmp")
    assert not _RECEIPT_PUBLISH_TEMP.fullmatch(prefix + "١٢٣.4.tmp")


def test_shared_volume_creation_waits_for_ownership_receipt(tmp_path: Path) -> None:
    """Another node cannot observe a volume before its creator records it."""

    backend = DockerComposeBackend(tmp_path)
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    volume = f"{ownership.project_name}_shared"
    created, release, second_entered = Event(), Event(), Event()
    state: dict[str, object] = {}
    creates = []

    def run(command, *, timeout):
        if command[:3] == ["docker", "volume", "inspect"]:
            labels = state.get("labels")
            return subprocess.CompletedProcess(
                command, int(labels is None), json.dumps(labels) if labels else "", ""
            )
        assert command[:3] == ["docker", "volume", "create"]
        creates.append(command)
        state["labels"] = {
            command[index + 1].split("=", 1)[0]: command[index + 1].split("=", 1)[1]
            for index, value in enumerate(command)
            if value == "--label"
        }
        created.set()
        assert release.wait(timeout=5)
        return subprocess.CompletedProcess(command, 0, volume + "\n", "")

    backend._run = run
    backend._raw_volume_inspect = lambda _name: {
        "Name": volume,
        "Labels": state["labels"],
    }

    def second() -> None:
        second_entered.set()
        backend._ensure_labeled_project_volume("shared")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result = pool.submit(backend._ensure_labeled_project_volume, "shared")
        try:
            assert created.wait(timeout=5)
            second_result = pool.submit(second)
            assert second_entered.wait(timeout=5)
            with pytest.raises(TimeoutError):
                second_result.result(timeout=0.1)
        finally:
            release.set()
        first_result.result(timeout=5)
        second_result.result(timeout=5)

    assert len(creates) == 1
    assert len(ownership.receipts("volume")) == 1


def test_compose_preflight_ignores_retired_network_identity(tmp_path: Path) -> None:
    """A restarted network is accepted only through its one live native ID."""

    backend = DockerComposeBackend(tmp_path)
    ownership = backend._ensure_resource_ownership(attempt_id="run-b")
    backend._docker_daemon_id = "daemon-a"
    name = f"{ownership.project_name}_security-net"
    for native_id, attempt_id in ((_ID_A, "run-a"), (_ID_B, "run-b")):
        ownership.record(
            ResourceReceipt(
                kind="network",
                native_id=native_id,
                external_name=name,
                semantic_name="security-net",
                node_address="provision.network.security-net",
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id="daemon-a",
                attempt_id=attempt_id,
            )
        )

    def inspect(network_id):
        if network_id != _ID_B:
            return {}
        return {
            "id": _ID_B,
            "name": name,
            "labels": {"com.docker.compose.project": ownership.project_name},
        }

    backend.host_inspect_network = MagicMock(side_effect=inspect)
    backend._verify_scoped_receipts(
        ownership,
        daemon_id="daemon-a",
        kind="network",
        selectors=(name,),
        resolver=backend._resolve_owned_network_id,
    )

    backend.host_inspect_network.side_effect = lambda network_id: {
        "id": network_id,
        "name": name,
        "labels": {"com.docker.compose.project": ownership.project_name},
    }
    with pytest.raises(OwnershipConflictError, match="absent or ambiguous"):
        backend._verify_scoped_receipts(
            ownership,
            daemon_id="daemon-a",
            kind="network",
            selectors=(name,),
            resolver=backend._resolve_owned_network_id,
        )


def test_container_action_uses_recorded_id_and_rejects_replacement(
    tmp_path: Path,
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name("aptl-victim")
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_ID_A,
            external_name=external,
            semantic_name="aptl-victim",
            node_address="provision.node.victim",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
        )
    )
    backend._docker_daemon_id = "daemon-a"
    container_info = {
        "Id": _ID_A,
        "Name": f"/{external}",
        "Config": {
            "Labels": {
                "aptl.workspace.id": ownership.workspace_id,
                "aptl.lifecycle.project": ownership.project_name,
            }
        },
    }
    backend._raw_container_inspect = MagicMock(return_value=container_info)
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    backend.container_exec("aptl-victim", ["true"])
    assert backend._run.call_args.args[0] == ["docker", "exec", _ID_A, "true"]

    backend._raw_container_inspect.return_value = {
        "Id": _ID_B,
        "Name": f"/{external}",
        "Config": {
            "Labels": {
                "aptl.workspace.id": ownership.workspace_id,
                "aptl.lifecycle.project": ownership.project_name,
            }
        },
    }
    with pytest.raises(OwnershipConflictError, match="native identity"):
        backend.container_exec("aptl-victim", ["true"])
    assert backend._run.call_count == 1


def test_cleanup_targets_only_receipt_owned_native_ids(tmp_path: Path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name("aptl-victim")
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_ID_A,
            external_name=external,
            semantic_name="aptl-victim",
            node_address="provision.node.victim",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
        )
    )
    backend._docker_daemon_id = "daemon-a"
    container_info = {
        "Id": _ID_A,
        "Name": f"/{external}",
        "Config": {
            "Labels": {
                "aptl.workspace.id": ownership.workspace_id,
                "aptl.lifecycle.project": ownership.project_name,
            }
        },
    }
    backend._raw_container_inspect = MagicMock(return_value=container_info)
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    assert backend.remove_generic_materializer_containers() == []
    # ``-v`` removes the container's anonymous volumes with it; receipt-owned
    # named volumes are untouched by it and retired separately.
    assert backend._run.call_args.args[0] == ["docker", "rm", "-f", "-v", _ID_A]
    assert all("--filter" not in call.args[0] for call in backend._run.call_args_list)


def test_workspace_state_contains_no_project_path_or_secret(tmp_path: Path) -> None:
    ownership = WorkspaceOwnership.ensure(tmp_path, "aptl")
    payload = json.loads(
        (tmp_path / ".aptl" / "lifecycle" / "workspace-ownership-v1.json").read_text(
            encoding="utf-8"
        )
    )

    assert payload == {"schema": 1, "workspace_id": ownership.workspace_id}
    assert str(tmp_path) not in json.dumps(payload)


def test_compose_start_scopes_external_names_and_records_native_ids(
    tmp_path: Path,
) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        """services:
  victim:
    image: example.invalid/victim:1
    container_name: aptl-victim
    hostname: victim
    labels:
      authored.identity: victim
""",
        encoding="utf-8",
    )
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    backend._docker_daemon_id = "daemon-a"

    inventory_calls = 0

    def fake_run(argv, **_kwargs):
        nonlocal inventory_calls
        if argv[:3] == ["docker", "ps", "-aq"]:
            inventory_calls += 1
            stdout = "" if inventory_calls == 1 else f"{_ID_A}\n"
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    backend._run = MagicMock(side_effect=fake_run)
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name("aptl-victim")
    container_info = {
        "Id": _ID_A,
        "Name": f"/{external}",
        "Config": {
            "Labels": {
                "aptl.workspace.id": ownership.workspace_id,
                "aptl.lifecycle.project": ownership.project_name,
                "aptl.attempt.id": "run-a",
                "com.docker.compose.project": ownership.project_name,
                "com.docker.compose.service": "victim",
                "authored.identity": "victim",
            },
            "Hostname": "victim",
        },
    }
    backend._raw_container_inspect = MagicMock(side_effect=[{}, container_info])

    result = backend.start([], build=False)

    assert result.success
    up = next(
        call.args[0] for call in backend._run.call_args_list if "up" in call.args[0]
    )
    assert up[up.index("-p") + 1] == ownership.project_name
    override_path = Path(up[up.index("-f", up.index("-f") + 1) + 1])
    override = yaml.safe_load(override_path.read_text(encoding="utf-8"))
    service = override["services"]["victim"]
    assert service["container_name"] == external
    assert service["labels"]["aptl.workspace.id"] == ownership.workspace_id
    assert service["labels"]["aptl.attempt.id"] == "run-a"
    assert "hostname" not in service
    receipt = ownership.candidates(
        "aptl-victim", kind="container", daemon_id="daemon-a"
    )
    assert receipt[0].native_id == _ID_A
    assert receipt[0].managed_by == "compose"


def test_two_workspaces_use_distinct_compose_projects_and_container_names(
    tmp_path: Path,
) -> None:
    names = []
    for root in (tmp_path / "one", tmp_path / "two"):
        root.mkdir()
        (root / "docker-compose.yml").write_text(
            "services:\n  victim:\n    image: example.invalid/victim:1\n"
            "    container_name: aptl-victim\n",
            encoding="utf-8",
        )
        backend = DockerComposeBackend(root, project_name="aptl")
        ownership = backend._ensure_resource_ownership(attempt_id="run-a")
        names.append((ownership.project_name, ownership.container_name("aptl-victim")))

    assert names[0][0] != names[1][0]
    assert names[0][1] != names[1][1]


def test_authored_labels_do_not_authorize_foreign_stopped_container(
    tmp_path: Path,
) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  victim:\n    image: example.invalid/victim:1\n"
    )
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"

    def fake_run(argv, **_kwargs):
        if argv[:3] == ["docker", "ps", "-aq"]:
            return subprocess.CompletedProcess(argv, 0, stdout=f"{_ID_A}\n", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    backend._run = MagicMock(side_effect=fake_run)
    backend._raw_container_inspect = MagicMock(
        return_value={
            "Id": _ID_A,
            "Name": f"/{ownership.container_name('aptl-victim')}",
            "Config": {
                "Labels": {
                    "aptl.workspace.id": ownership.workspace_id,
                    "aptl.lifecycle.project": ownership.project_name,
                    "com.docker.compose.project": ownership.project_name,
                }
            },
        }
    )

    result = backend.start([], build=False)

    assert not result.success
    assert "ownership conflict" in result.error.lower()
    assert not any("up" in call.args[0] for call in backend._run.call_args_list)
    backend._raw_container_inspect.assert_not_called()


def test_network_creation_records_native_id_and_cleanup_uses_only_that_id(
    tmp_path: Path,
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout=f"{_ID_A}\n", stderr="")
    )

    result = backend.create_network(DeploymentNetworkRealization(name="dmz-net"))

    assert result.success
    receipt = ownership.candidates("dmz-net", kind="network", daemon_id="daemon-a")
    assert receipt[0].native_id == _ID_A
    create = backend._run.call_args.args[0]
    assert f"aptl.workspace.id={ownership.workspace_id}" in create
    backend.host_inspect_network = MagicMock(
        return_value={
            "id": _ID_A,
            "name": result.message,
            "labels": {"com.docker.compose.project": ownership.project_name},
        }
    )
    backend._run.reset_mock()
    backend._run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")

    assert backend.remove_project_networks() == []
    assert backend._run.call_args.args[0] == ["docker", "network", "rm", _ID_A]
    assert all("--filter" not in call.args[0] for call in backend._run.call_args_list)


def test_network_namespace_discovery_uses_full_receipted_native_ids(
    tmp_path: Path,
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    external_name = f"{ownership.project_name}_dmz"
    ownership.record(
        ResourceReceipt(
            kind="network",
            native_id=_ID_A,
            external_name=external_name,
            semantic_name="dmz",
            node_address="dmz",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
            managed_by="direct",
        )
    )

    def fake_run(argv, **_kwargs):
        if argv[:3] == ["docker", "network", "ls"]:
            native_id = _ID_A if "--no-trunc" in argv else _ID_A[:12]
            return subprocess.CompletedProcess(argv, 0, f"{native_id}\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    backend._run = MagicMock(side_effect=fake_run)
    backend.host_inspect_network = MagicMock(
        return_value={
            "id": _ID_A,
            "name": external_name,
            "labels": {"com.docker.compose.project": ownership.project_name},
        }
    )

    backend._verify_compose_namespace_is_owned(ownership, "daemon-a")

    network_list = next(
        call.args[0]
        for call in backend._run.call_args_list
        if call.args[0][:3] == ["docker", "network", "ls"]
    )
    assert "--no-trunc" in network_list


def test_container_namespace_discovery_uses_full_receipted_native_ids(
    tmp_path: Path,
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    external_name = ownership.container_name("aptl-victim")
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_ID_A,
            external_name=external_name,
            semantic_name="aptl-victim",
            node_address="victim",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
            managed_by="compose",
        )
    )

    def fake_run(argv, **_kwargs):
        if argv[:3] == ["docker", "ps", "-aq"]:
            native_id = _ID_A if "--no-trunc" in argv else _ID_A[:12]
            return subprocess.CompletedProcess(argv, 0, f"{native_id}\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    backend._run = MagicMock(side_effect=fake_run)
    backend._raw_container_inspect = MagicMock(
        return_value={
            "Id": _ID_A,
            "Name": f"/{external_name}",
            "Config": {
                "Labels": {
                    "aptl.workspace.id": ownership.workspace_id,
                    "aptl.lifecycle.project": ownership.project_name,
                }
            },
        }
    )

    backend._verify_compose_namespace_is_owned(ownership, "daemon-a")

    container_list = next(
        call.args[0]
        for call in backend._run.call_args_list
        if call.args[0][:3] == ["docker", "ps", "-aq"]
    )
    assert "--no-trunc" in container_list


def test_volume_cleanup_uses_receipt_and_never_prefix_discovery(tmp_path: Path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    volume = f"{ownership.project_name}_data"
    ownership.record(
        ResourceReceipt(
            kind="volume",
            native_id=volume,
            external_name=volume,
            semantic_name="data",
            node_address="data",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
        )
    )
    inspected = json.dumps(
        [
            {
                "Name": volume,
                "Labels": {"com.docker.compose.project": ownership.project_name},
            }
        ]
    )

    present = True

    def fake_run(argv, **_kwargs):
        nonlocal present
        if argv[:3] == ["docker", "volume", "rm"]:
            present = False
        inspect_cmd = argv[:3] == ["docker", "volume", "inspect"]
        stdout = inspected if inspect_cmd and present else ""
        return subprocess.CompletedProcess(
            argv, 0 if not inspect_cmd or present else 1, stdout=stdout, stderr=""
        )

    backend._run = MagicMock(side_effect=fake_run)

    assert backend._remove_owned_volumes() == []
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert ["docker", "volume", "rm", volume] in commands
    assert all("ls" not in command for command in commands)
    assert ownership.receipts("volume") == ()


def test_clean_volume_cleanup_retires_already_absent_receipt(tmp_path: Path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    volume = f"{ownership.project_name}_data"
    receipt = ResourceReceipt(
        kind="volume",
        native_id=volume,
        external_name=volume,
        semantic_name="data",
        node_address="data",
        workspace_id=ownership.workspace_id,
        project_name=ownership.project_name,
        daemon_id="daemon-a",
        attempt_id="run-a",
    )
    ownership.record(receipt)
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="")
    )

    assert backend._remove_owned_volumes() == []
    assert ownership.receipts("volume") == ()

    ownership.record(ResourceReceipt(**{**receipt.__dict__, "attempt_id": "run-b"}))
    assert ownership.receipts("volume")[0].attempt_id == "run-b"


def test_receipted_container_resolution_retries_only_inconclusive_inspect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    external_name = ownership.container_name("worker")
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_ID_A,
            external_name=external_name,
            semantic_name="worker",
            node_address="provision.node.worker",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
        )
    )
    current = {
        "Id": _ID_A,
        "Name": f"/{external_name}",
        "Config": {
            "Labels": {
                "aptl.workspace.id": ownership.workspace_id,
                "aptl.lifecycle.project": ownership.project_name,
            }
        },
    }
    sleeps: list[float] = []
    monkeypatch.setattr(
        "aptl.core.deployment._compose_resource_resolution.time.sleep",
        sleeps.append,
    )
    backend._raw_container_inspect = MagicMock(side_effect=[{}, current])

    assert backend._resolve_owned_container_id("worker") == _ID_A
    assert sleeps == [0.2]
    assert backend._raw_container_inspect.call_count == 2

    backend._raw_container_inspect = MagicMock(
        return_value={
            **current,
            "Config": {"Labels": {"aptl.workspace.id": "foreign"}},
        }
    )
    sleeps.clear()
    with pytest.raises(OwnershipConflictError, match="labels changed"):
        backend._resolve_owned_container_id("worker")
    assert sleeps == []
    assert backend._raw_container_inspect.call_count == 1


def test_compose_override_labels_networks_and_volumes_and_plans_exact_names(
    tmp_path: Path,
) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """services:
  victim:
    image: example.invalid/victim:1
    networks: [dmz]
    volumes: [data:/data]
networks:
  dmz: {}
volumes:
  data: {}
"""
    )
    ownership = WorkspaceOwnership.ensure(tmp_path, "aptl")

    override_path, _semantic, expected = write_compose_ownership_override(
        ownership, attempt_id="run-a", compose_files=(compose,)
    )

    override = yaml.safe_load(override_path.read_text(encoding="utf-8"))
    assert expected["network"] == (f"{ownership.project_name}_dmz",)
    assert expected["volume"] == (f"{ownership.project_name}_data",)
    assert override["networks"]["dmz"]["labels"]["aptl.attempt.id"] == "run-a"
    assert override["volumes"]["data"]["labels"]["aptl.workspace.id"] == (
        ownership.workspace_id
    )


def test_compose_override_scopes_network_mode_to_receipted_direct_container(
    tmp_path: Path,
) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """services:
  capture:
    image: example.invalid/capture:1
    network_mode: container:aptl-kali
"""
    )
    ownership = WorkspaceOwnership.ensure(tmp_path, "aptl")
    direct_name = ownership.container_name("aptl-kali")
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_ID_A,
            external_name=direct_name,
            semantic_name="aptl-kali",
            node_address="provision.node.kali",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="daemon-a",
            attempt_id="run-a",
        )
    )

    override_path, _semantic, expected = write_compose_ownership_override(
        ownership, attempt_id="run-a", compose_files=(compose,)
    )

    override = yaml.safe_load(override_path.read_text(encoding="utf-8"))
    assert override["services"]["capture"]["network_mode"] == (
        f"container:{direct_name}"
    )
    assert direct_name in expected["container"]


@pytest.mark.parametrize("kind", ["network", "volume"])
def test_unlabelled_exact_name_collision_fails_before_compose_up(
    tmp_path: Path, kind: str
) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """services:
  victim:
    image: example.invalid/victim:1
    networks: [dmz]
    volumes: [data:/data]
networks:
  dmz: {}
volumes:
  data: {}
"""
    )
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    expected_name = f"{ownership.project_name}_{'dmz' if kind == 'network' else 'data'}"

    def fake_run(argv, **_kwargs):
        if argv[:3] == ["docker", "network", "inspect"]:
            stdout = (
                json.dumps(
                    [
                        {
                            "Id": _ID_A,
                            "Name": expected_name,
                            "Driver": "bridge",
                            "IPAM": {"Config": [{}]},
                            "Labels": {},
                            "Containers": {},
                        }
                    ]
                )
                if kind == "network" and argv[3] == expected_name
                else ""
            )
            return subprocess.CompletedProcess(argv, 0 if stdout else 1, stdout, "")
        if argv[:3] == ["docker", "volume", "inspect"]:
            stdout = (
                json.dumps([{"Name": expected_name, "Labels": {}}])
                if kind == "volume" and argv[3] == expected_name
                else ""
            )
            return subprocess.CompletedProcess(argv, 0 if stdout else 1, stdout, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    backend._run = MagicMock(side_effect=fake_run)

    result = backend.start([], build=False)

    assert not result.success
    assert "ownership conflict" in result.error.lower()
    assert not any("up" in call.args[0] for call in backend._run.call_args_list)


def test_network_attachment_resolves_both_resource_ids(tmp_path: Path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    backend._resolve_owned_container_id = MagicMock(return_value=_ID_A)
    backend._resolve_owned_network_id = MagicMock(return_value=_ID_B)
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    assert backend.connect_container_network("victim", "dmz").success
    assert backend._run.call_args.args[0] == [
        "docker",
        "network",
        "connect",
        _ID_B,
        _ID_A,
    ]

    assert backend.disconnect_container_network("victim", "dmz").success
    assert backend._run.call_args.args[0] == [
        "docker",
        "network",
        "disconnect",
        _ID_B,
        _ID_A,
    ]


def test_network_reuse_inspects_the_verified_id_not_the_name(tmp_path: Path) -> None:
    """Verification must stay bound to the object ownership just verified.

    `_resolve_owned_network_id` returns the receipt-bound native id. Re-inspecting
    by the mutable name instead let a same-name replacement between the two calls
    redirect the policy check onto a different network (issue #1105).
    """
    from aptl.core.deployment.realization import DeploymentNetworkRealization

    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    backend._resolve_owned_network_id = MagicMock(return_value=_ID_B)
    backend.host_inspect_network = MagicMock(return_value={})

    backend._realization_network_reuse_failures(
        "aptl_aptl-dmz",
        DeploymentNetworkRealization(name="dmz", cidr="172.31.0.0/24"),
    )

    backend.host_inspect_network.assert_called_once_with(_ID_B)


@pytest.mark.parametrize(
    "failing_stage",
    ["container", "network", "volume"],
)
def test_a_failed_capture_rolls_the_whole_attempt_back(
    tmp_path: Path, failing_stage: str
) -> None:
    """Whatever stage fails, nothing this attempt created may be left behind.

    The rollback used to remove only receipted containers, so the object whose
    receipt failed — and every network and volume created alongside it — stayed
    on the daemon with no receipt. The next preflight read that as a foreign
    namespace and the workspace could neither start nor clean up (issue #1105).
    """
    from aptl.core.deployment._compose_owned_start import _OwnedStartScope

    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership()
    scope = _OwnedStartScope(
        ownership=ownership,
        attempt_id="attempt-under-test",
        daemon_id="daemon",
        compose_files=(tmp_path / "docker-compose.yml",),
        semantic_by_service={},
    )

    def boom(*args, **kwargs):
        raise OwnershipConflictError(f"{failing_stage} capture failed")

    stages = {
        "container": "_record_compose_container_receipts",
        "network": "_record_compose_network_receipts",
        "volume": "_record_compose_volume_receipts",
    }
    for name, attr in stages.items():
        setattr(
            backend,
            attr,
            boom if name == failing_stage else (lambda *a, **k: None),
        )
    backend._remove_owned_attempt_containers = MagicMock()
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    result = backend._capture_started_resources(scope, ["core"])

    assert not result.success
    [rollback] = [c.args[0] for c in backend._run.call_args_list]
    assert "down" in rollback
    # Volumes and orphans included: an unreceipted network or volume is exactly
    # what a container-only rollback used to strand.
    assert "--volumes" in rollback
    assert "--remove-orphans" in rollback
    backend._remove_owned_attempt_containers.assert_called_once_with(
        "attempt-under-test"
    )


def test_a_successful_capture_rolls_nothing_back(tmp_path: Path) -> None:
    from aptl.core.deployment._compose_owned_start import _OwnedStartScope

    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    scope = _OwnedStartScope(
        ownership=backend._ensure_resource_ownership(),
        attempt_id="attempt-under-test",
        daemon_id="daemon",
        compose_files=(tmp_path / "docker-compose.yml",),
        semantic_by_service={},
    )
    for attr in (
        "_record_compose_container_receipts",
        "_record_compose_network_receipts",
        "_record_compose_volume_receipts",
    ):
        setattr(backend, attr, lambda *a, **k: None)
    backend._run = MagicMock()

    assert backend._capture_started_resources(scope, ["core"]).success
    backend._run.assert_not_called()


def test_a_failed_compose_up_receipts_and_rolls_back_partial_runtime(
    tmp_path: Path,
) -> None:
    """A non-zero Compose up must not strand unreceipted runtime objects."""
    from aptl.core.deployment._compose_owned_start import _OwnedStartScope

    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    scope = _OwnedStartScope(
        ownership=backend._ensure_resource_ownership(),
        attempt_id="attempt-under-test",
        daemon_id="daemon",
        compose_files=(tmp_path / "docker-compose.yml",),
        semantic_by_service={},
    )
    backend._prepare_owned_start = MagicMock(return_value=scope)
    backend._owned_up_command = MagicMock(return_value=["docker", "compose", "up"])
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess(
            [], 1, stdout="", stderr="service failed"
        )
    )
    backend._capture_started_resources = MagicMock(
        return_value=LabResult(success=True)
    )
    backend._roll_back_started_project = MagicMock()

    result = backend._run_owned_compose_up(
        ["core"],
        build=False,
        compose_files=scope.compose_files,
        exclude_services=(),
        only_services=(),
        scenario_root=None,
    )

    assert not result.success
    assert result.error == "service failed"
    backend._capture_started_resources.assert_called_once_with(scope, ["core"])
    backend._roll_back_started_project.assert_called_once_with(
        scope, ["core"], remove_volumes=False
    )
