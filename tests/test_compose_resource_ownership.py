"""Workspace-scoped native-resource ownership for Compose backends (issue #964)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    ResourceReceipt,
    WorkspaceOwnership,
    write_compose_ownership_override,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import DeploymentNetworkRealization
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
    with pytest.raises(OwnershipConflictError, match="immutable ownership receipt"):
        ownership.record(ResourceReceipt(**{**receipt.__dict__, "attempt_id": "run-b"}))
    with pytest.raises(OwnershipConflictError, match="daemon identity"):
        ownership.candidates("aptl-victim", kind="container", daemon_id="daemon-b")


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
    assert backend._run.call_args.args[0] == ["docker", "rm", "-f", _ID_A]
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

    def fake_run(argv, **_kwargs):
        stdout = inspected if argv[:3] == ["docker", "volume", "inspect"] else ""
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    backend._run = MagicMock(side_effect=fake_run)

    assert backend._remove_owned_volumes() == []
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert ["docker", "volume", "rm", volume] in commands
    assert all("ls" not in command for command in commands)


def test_isolated_daemon_children_are_receipted_before_observation(
    tmp_path: Path,
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl")
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "daemon-a"
    backend._attempt_isolated_docker_daemon = True
    requirement = DeploymentSpawnImageRequirement(
        node_address="provision.node.orborus",
        authority_id="orborus",
        template_id="worker",
        image_ref="example.invalid/worker@sha256:" + "c" * 64,
        execution_timeout_seconds=30,
        child_label="com.example.execution=run-a",
        expected_count=1,
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout=f"{_ID_A}\n", stderr="")
    )
    backend._raw_container_inspect = MagicMock(
        return_value={
            "Id": _ID_A,
            "Name": "/runtime-worker",
            "Config": {"Labels": {"com.example.execution": "run-a"}},
        }
    )

    failure, identifiers = backend._correlated_child_ids(
        requirement, require_children=True
    )

    assert failure is None
    assert identifiers == (_ID_A,)
    assert backend._resolve_owned_container_id("worker") == _ID_A
    receipt = ownership.candidates("worker", kind="container", daemon_id="daemon-a")
    assert receipt[0].managed_by == "child"
    backend._docker_daemon_id = "daemon-b"
    with pytest.raises(OwnershipConflictError, match="daemon identity"):
        backend._resolve_owned_container_id("worker")


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
