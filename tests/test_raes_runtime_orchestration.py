"""Runtime-orchestration authority lowering and image-closure guards (#949)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import os
import stat
import subprocess
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_excess import _has_undeclared_mounts
from aptl.backends.raes_runtime_orchestration import (
    admit_docker_authorities,
    docker_control_authorities,
    prepare_runtime_orchestration_for_scenario,
    spawn_image_requirements,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    deployment_spawn_image_requirements,
    effective_orchestration_model_errors,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    DeploymentServicePort,
)
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DeploymentSpawnImageRequirement,
)

_DIGEST = "sha256:" + "a" * 64
_CHILD_REF = f"ghcr.io/example/worker@{_DIGEST}"
_IMAGE_ID = "sha256:" + "b" * 64
_CHILD_INSPECT = f'["{_CHILD_REF}"]\t{_IMAGE_ID}\tlinux/amd64\n'


def _runtime(*, image_ref: str = _CHILD_REF) -> RuntimeConfiguration:
    return RuntimeConfiguration.model_validate(
        {
            "local_control_interfaces": [
                {
                    "control_interface_id": "docker-sock",
                    "path": "/var/run/docker.sock",
                    "bind_source": "/var/run/docker.sock",
                    "kind": "unix_socket",
                    "access": "read_write",
                }
            ],
            "orchestration_authorities": [
                {
                    "orchestration_authority_id": "worker-runtime",
                    "control_interface_ref": "docker-sock",
                    "engine": "docker",
                    "privilege_class": "host_root_equivalent",
                    "spawn_templates": [
                        {"template_id": "worker", "image_ref": image_ref}
                    ],
                    "lifecycle_policy": {"execution_timeout": "600"},
                    "realized_children": [
                        {
                            "workload_id": "worker-instance",
                            "image_ref": image_ref,
                            "count": 1,
                            "evidence_ref": (
                                "docker-label:org.aptl.authority=worker-runtime"
                            ),
                        }
                    ],
                }
            ],
        }
    )


def _spec(runtime: RuntimeConfiguration | None = None) -> DeploymentRealizationSpec:
    runtime = runtime or _runtime()
    node = DeploymentNodeRealization(
        address="provision.node.orborus",
        name="orborus",
        service_name="orborus",
        container_name="aptl-orborus",
        networks=("security-net",),
        runtime=runtime,
        profiles=("soc",),
    )
    return DeploymentRealizationSpec(
        profiles=("soc",),
        nodes=(node,),
        networks=(DeploymentNetworkRealization(name="security-net"),),
        docker_authority_admissions=admit_docker_authorities((node,)),
        images=(
            DeploymentImageRealization(
                address="provision.node.orborus",
                service_name="orborus",
                source_name="ghcr.io/example/orborus",
                source_version=_DIGEST,
                image_ref=f"ghcr.io/example/orborus@{_DIGEST}",
                mode="pull",
                policy_rule="authored-exact-artifact",
            ),
        ),
    )


def test_same_node_authority_join_and_child_closure_are_preserved() -> None:
    runtime = _runtime()

    bindings = docker_control_authorities(
        runtime, node_address="provision.node.orborus"
    )
    requirements = spawn_image_requirements(
        runtime, node_address="provision.node.orborus"
    )

    assert len(bindings) == 1
    authority, interface = bindings[0]
    assert authority.control_interface_ref == interface.control_interface_id
    assert interface.bind_source == interface.path == "/var/run/docker.sock"
    assert requirements == (
        DeploymentSpawnImageRequirement(
            node_address="provision.node.orborus",
            authority_id="worker-runtime",
            template_id="worker",
            image_ref=_CHILD_REF,
            execution_timeout_seconds=600,
            child_label="org.aptl.authority=worker-runtime",
            expected_count=1,
        ),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bind_source", "/tmp/docker.sock"),
        ("path", "/tmp/docker.sock"),
        ("kind", "file"),
        ("access", "read_only"),
    ],
)
def test_control_authority_rejects_every_noncanonical_socket_tuple(
    field: str, value: str
) -> None:
    payload = _runtime().model_dump(mode="json")
    payload["local_control_interfaces"][0][field] = value
    runtime = RuntimeConfiguration.model_validate(payload)

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-control-interface-invalid"
    ):
        docker_control_authorities(runtime, node_address="provision.node.orborus")


@pytest.mark.parametrize(
    ("authority_field", "value"),
    [("engine", "podman"), ("privilege_class", "namespaced")],
)
def test_control_authority_rejects_unsupported_engine_or_privilege(
    authority_field: str, value: str
) -> None:
    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0][authority_field] = value
    runtime = RuntimeConfiguration.model_validate(payload)

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-control-interface-invalid"
    ):
        docker_control_authorities(
            runtime,
            node_address="provision.node.orborus",
        )


def test_mutable_spawn_template_is_not_an_immutable_image_requirement() -> None:
    runtime = _runtime(image_ref="ghcr.io/example/worker:latest")

    with pytest.raises(
        ValueError, match="aptl.provisioner.spawn-image-identity-invalid"
    ):
        spawn_image_requirements(
            runtime,
            node_address="provision.node.orborus",
        )


def test_unbounded_child_lifecycle_is_rejected() -> None:
    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0]["lifecycle_policy"] = {}
    runtime = RuntimeConfiguration.model_validate(payload)

    with pytest.raises(
        ValueError, match="aptl.provisioner.orchestration-lifecycle-unbounded"
    ):
        spawn_image_requirements(
            runtime,
            node_address="provision.node.orborus",
        )


def test_empty_spawn_closure_is_rejected() -> None:
    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0]["spawn_templates"] = []
    runtime = RuntimeConfiguration.model_validate(payload)

    with pytest.raises(
        ValueError, match="aptl.provisioner.spawn-image-identity-invalid"
    ):
        spawn_image_requirements(
            runtime,
            node_address="provision.node.orborus",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload["orchestration_authorities"][0].update(
            realized_children=[]
        ),
        lambda payload: payload["orchestration_authorities"][0]["realized_children"][
            0
        ].update(evidence_ref="run-id:worker-runtime"),
        lambda payload: payload["orchestration_authorities"][0]["realized_children"][
            0
        ].update(count=0),
        lambda payload: payload["orchestration_authorities"][0]["realized_children"][
            0
        ].update(image_ref=f"ghcr.io/example/other@{_DIGEST}"),
    ],
)
def test_spawn_child_correlation_must_be_complete_and_exact(
    mutation: Callable[[dict[str, object]], None],
) -> None:
    payload = _runtime().model_dump(mode="json")
    mutation(payload)
    runtime = RuntimeConfiguration.model_validate(payload)

    with pytest.raises(
        ValueError, match="aptl.provisioner.spawn-child-correlation-invalid"
    ):
        spawn_image_requirements(
            runtime,
            node_address="provision.node.orborus",
        )


def test_spawn_child_labels_are_unique_across_authorities() -> None:
    first = _spec().nodes[0]
    second = replace(
        first,
        address="provision.node.second",
        name="second",
        service_name="second",
        container_name="aptl-second",
    )
    with pytest.raises(
        ValueError, match="aptl.provisioner.spawn-child-correlation-invalid"
    ):
        admit_docker_authorities((first, second))


def test_graph_admission_rejects_participant_profile_authority_holder() -> None:
    holder = replace(_spec().nodes[0], profiles=("kali",))

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-not-management-only"
    ):
        admit_docker_authorities((holder,))


def test_graph_admission_rejects_participant_serving_authority_holder() -> None:
    holder = replace(
        _spec().nodes[0],
        services=(DeploymentServicePort(name="participant-api", port=8080),),
    )

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-not-management-only"
    ):
        admit_docker_authorities((holder,))


def test_effective_model_rejects_missing_graph_admission() -> None:
    payload = {
        "services": {
            "orborus": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ]
            }
        }
    }

    errors = effective_orchestration_model_errors(
        payload, replace(_spec(), docker_authority_admissions=())
    )

    assert errors == ["Docker socket bind appears on unauthorized service orborus."]


def test_core_rejects_stale_carried_admission_without_reading_raes() -> None:
    admission = replace(_spec().docker_authority_admissions[0], service_name="stale")
    stale_spec = replace(_spec(), docker_authority_admissions=(admission,))

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-admission-invalid"
    ):
        deployment_spawn_image_requirements(stale_spec)


def test_multiple_docker_authorities_on_one_node_are_rejected() -> None:
    payload = _runtime().model_dump(mode="json")
    second = dict(payload["orchestration_authorities"][0])
    second["orchestration_authority_id"] = "second-runtime"
    payload["orchestration_authorities"].append(second)
    runtime = RuntimeConfiguration.model_validate(payload)

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-control-interface-invalid"
    ):
        docker_control_authorities(
            runtime,
            node_address="provision.node.orborus",
        )


def test_scenario_preparation_binds_endpoint_before_other_docker_work() -> None:
    calls: list[str] = []
    backend = MagicMock()
    backend.bind_local_docker_socket.side_effect = lambda: (
        calls.append("bind") or LabResult(success=True)
    )
    scenario = SimpleNamespace(nodes={"orborus": SimpleNamespace(runtime=_runtime())})

    result = prepare_runtime_orchestration_for_scenario(scenario, backend)

    assert calls == ["bind"]
    assert result is None


def test_scenario_preparation_does_not_require_downstream_pack_identity() -> None:
    backend = MagicMock()
    backend.bind_local_docker_socket.return_value = LabResult(success=True)
    scenario = SimpleNamespace(
        nodes={
            "orborus": SimpleNamespace(
                runtime=_runtime(image_ref="ghcr.io/example/worker:latest")
            )
        }
    )

    assert prepare_runtime_orchestration_for_scenario(scenario, backend) is None
    backend.bind_local_docker_socket.assert_called_once_with()


def test_public_plan_binds_authority_before_artifact_availability(
    tmp_path, monkeypatch
) -> None:
    from aptl.backends import raes

    calls: list[str] = []
    bundle = SimpleNamespace(sdl_path=tmp_path / "scenario.yaml", root=tmp_path)
    scenario = SimpleNamespace(nodes={})
    monkeypatch.setattr(raes, "resolve_scenario_bundle", lambda *_args: bundle)
    monkeypatch.setattr(raes, "parse_sdl_file", lambda _path: scenario)
    monkeypatch.setattr(
        raes,
        "prepare_runtime_orchestration_for_scenario",
        lambda *_args: calls.append("bind"),
    )

    def _availability(*_args, **_kwargs):
        calls.append("availability")
        raise RuntimeError("stop after ordering proof")

    monkeypatch.setattr(raes, "artifact_availability_for_scenario", _availability)
    backend = MagicMock()
    config = AptlConfig()

    with pytest.raises(RuntimeError, match="ordering proof"):
        raes._plan_scenario(tmp_path, config, backend, None, None)

    assert calls == ["bind", "availability"]


def test_generated_compose_lowers_one_long_form_socket_bind() -> None:
    from aptl.core.deployment._compose_node_generation import render_realization_compose

    service = render_realization_compose(_spec())["services"]["orborus"]

    assert service["volumes"] == [
        {
            "type": "bind",
            "source": "/var/run/docker.sock",
            "target": "/var/run/docker.sock",
            "read_only": False,
        }
    ]
    assert service.get("privileged") is not True


def test_generated_compose_preserves_existing_volumes_when_adding_socket(
    monkeypatch,
) -> None:
    from aptl.core.deployment import _compose_node_generation as generation

    declared = {"type": "tmpfs", "target": "/work"}
    monkeypatch.setattr(
        generation,
        "_operational_config",
        lambda _runtime: {"volumes": [declared]},
    )

    service = generation.render_realization_compose(_spec())["services"]["orborus"]

    assert service["volumes"] == [
        declared,
        {
            "type": "bind",
            "source": "/var/run/docker.sock",
            "target": "/var/run/docker.sock",
            "read_only": False,
        },
    ]


def test_authority_holder_without_compose_image_is_rejected_before_realization(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)

    result = backend._validate_runtime_orchestration_route(replace(_spec(), images=()))

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Docker control authority requires a Compose image for provision.node.orborus."
    )


def test_effective_compose_rejects_duplicate_or_endpoint_redirects() -> None:
    mount = {
        "type": "bind",
        "source": "/var/run/docker.sock",
        "target": "/var/run/docker.sock",
        "read_only": False,
    }
    payload = {
        "services": {
            "orborus": {
                "volumes": [mount, dict(mount)],
                "environment": {"DOCKER_HOST": "tcp://docker.example:2375"},
            },
            "worker": {"volumes": [dict(mount)]},
        }
    }

    errors = effective_orchestration_model_errors(payload, _spec())

    assert any("exactly one" in error for error in errors)
    assert any("endpoint override" in error for error in errors)
    assert any("unauthorized service" in error for error in errors)


def test_effective_compose_rejects_privileged_authority_holder() -> None:
    render_payload = {
        "services": {
            "orborus": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                        "read_only": False,
                    }
                ],
                "privileged": True,
            }
        }
    }

    assert any(
        "must not be privileged" in error
        for error in effective_orchestration_model_errors(render_payload, _spec())
    )


@pytest.mark.parametrize("source", ["/", "/var/run", "/socket-alias"])
def test_effective_compose_rejects_socket_ancestor_and_alias_binds(
    source: str, monkeypatch
) -> None:
    if source == "/socket-alias":
        realpath = os.path.realpath
        monkeypatch.setattr(
            os.path,
            "realpath",
            lambda path: "/var/run/docker.sock" if path == source else realpath(path),
        )
    payload = {
        "services": {
            "worker": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": source,
                        "target": "/host",
                    }
                ]
            },
            "orborus": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ]
            },
        }
    }

    assert any(
        "unauthorized service worker" in error
        for error in effective_orchestration_model_errors(payload, _spec())
    )


def test_effective_compose_accepts_omitted_read_write_default() -> None:
    payload = {
        "services": {
            "orborus": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ]
            }
        }
    }

    assert effective_orchestration_model_errors(payload, _spec()) == []


def test_raw_raes_authority_does_not_admit_the_control_socket_mount() -> None:
    runtime = _runtime()
    socket_mount = {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "RW": True,
    }

    assert _has_undeclared_mounts([socket_mount], [], runtime)
    assert not _has_undeclared_mounts(
        [socket_mount], [], runtime, docker_authority_admitted=True
    )
    assert _has_undeclared_mounts(
        [socket_mount, {"Type": "bind", "Destination": "/host", "RW": True}],
        [],
        runtime,
        docker_authority_admitted=True,
    )
    assert _has_undeclared_mounts(
        [{**socket_mount, "Source": "/tmp/docker.sock"}],
        [],
        runtime,
        docker_authority_admitted=True,
    )
    assert _has_undeclared_mounts(
        [{**socket_mount, "RW": False}],
        [],
        runtime,
        docker_authority_admitted=True,
    )


@pytest.mark.parametrize("source", ["/", "/var/run", "/socket-alias"])
def test_control_socket_ancestor_and_alias_binds_are_never_admitted(
    source: str, monkeypatch
) -> None:
    if source == "/socket-alias":
        realpath = os.path.realpath
        monkeypatch.setattr(
            os.path,
            "realpath",
            lambda path: "/var/run/docker.sock" if path == source else realpath(path),
        )
    runtime = _runtime()
    mount = {
        "Type": "bind",
        "Source": source,
        "Destination": "/declared",
        "RW": True,
    }

    assert _has_undeclared_mounts(
        [mount],
        [SimpleNamespace(target="/declared")],
        runtime,
        docker_authority_admitted=True,
    )


def test_authority_holder_accepts_only_its_carried_declared_mount_footprint(
    tmp_path,
) -> None:
    payload = _runtime().model_dump(mode="json")
    payload["mounts"] = [
        {
            "target": "/data",
            "source": "/host/data",
            "source_kind": "bind",
            "read_only": True,
        }
    ]
    spec = _spec(RuntimeConfiguration.model_validate(payload))
    admission = spec.docker_authority_admissions[0]
    assert admission.allowed_mount_targets == ("/data",)

    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    holder = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            },
            {
                "Type": "bind",
                "Source": "/host/data",
                "Destination": "/data",
                "RW": False,
            },
        ],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    backend.container_inspect = MagicMock(return_value=holder)
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )

    assert backend._runtime_authority_matches("aptl-orborus", admission)

    holder["Mounts"].append(
        {
            "Type": "bind",
            "Source": "/host/secret",
            "Destination": "/secret",
            "RW": False,
        }
    )
    assert not backend._runtime_authority_matches("aptl-orborus", admission)


def test_local_backend_binds_commands_to_observed_socket_identity(
    tmp_path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path)
    socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=42)
    monkeypatch.setattr(os, "lstat", lambda _path: socket_stat)
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    monkeypatch.setenv("DOCKER_HOST", "tcp://wrong.example:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "wrong-context")
    run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    monkeypatch.setattr("subprocess.run", run)

    result = backend.bind_local_docker_socket()

    assert result.success is True
    kwargs = run.call_args.kwargs
    assert kwargs["env"]["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert "DOCKER_CONTEXT" not in kwargs["env"]
    assert backend.revalidate_local_docker_socket().success is True


@pytest.mark.parametrize(
    ("mode", "accessible"),
    [(stat.S_IFREG, True), (stat.S_IFSOCK, False)],
)
def test_wrong_or_inaccessible_socket_fails_with_stable_error(
    tmp_path, monkeypatch, mode: int, accessible: bool
) -> None:
    backend = DockerComposeBackend(tmp_path)
    monkeypatch.setattr(
        os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=mode, st_dev=9, st_ino=42),
    )
    monkeypatch.setattr(os, "access", lambda _path, _mode: accessible)

    result = backend.bind_local_docker_socket()

    assert result.success is False
    assert result.error == "Docker control endpoint unavailable."


def test_missing_socket_fails_with_stable_error(tmp_path, monkeypatch) -> None:
    backend = DockerComposeBackend(tmp_path)

    def _missing(_path):
        raise FileNotFoundError

    monkeypatch.setattr(os, "lstat", _missing)

    result = backend.bind_local_docker_socket()

    assert result.success is False
    assert result.error == "Docker control endpoint unavailable."


def test_replaced_socket_or_daemon_identity_fails_closed(tmp_path, monkeypatch) -> None:
    backend = DockerComposeBackend(tmp_path)
    stats = iter(
        [
            SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=42),
            SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=42),
            SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=43),
        ]
    )
    monkeypatch.setattr(os, "lstat", lambda _path: next(stats))
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    monkeypatch.setattr(
        backend,
        "_run",
        MagicMock(
            return_value=subprocess.CompletedProcess(
                [], 0, stdout="daemon-a\n", stderr=""
            )
        ),
    )

    assert backend.bind_local_docker_socket().success is True
    result = backend.revalidate_local_docker_socket()

    assert result.success is False
    assert result.error == "Docker control endpoint identity changed."


def test_socket_replaced_while_initial_identity_is_bound_fails_closed(
    tmp_path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path)
    stats = iter(
        [
            SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=42),
            SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=43),
        ]
    )
    monkeypatch.setattr(os, "lstat", lambda _path: next(stats))
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )

    result = backend.bind_local_docker_socket()

    assert result.success is False
    assert result.error == "Docker control endpoint identity changed."


def test_changed_daemon_identity_fails_closed(tmp_path, monkeypatch) -> None:
    backend = DockerComposeBackend(tmp_path)
    socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=42)
    monkeypatch.setattr(os, "lstat", lambda _path: socket_stat)
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="daemon-b\n", stderr=""),
        ]
    )

    assert backend.bind_local_docker_socket().success is True
    result = backend.revalidate_local_docker_socket()

    assert result.success is False
    assert result.error == "Docker control endpoint identity changed."


def test_offline_child_image_verification_never_calls_registry(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=SimpleNamespace(success=True)
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._prepare_spawn_images(_spec())

    assert result is None
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert commands[0][:2] == ["docker", "version"]
    assert commands[1][:3] == ["docker", "image", "inspect"]
    assert all("pull" not in command for command in commands)
    assert all("manifest" not in command for command in commands)


def test_offline_child_image_platform_mismatch_is_stable_and_bounded(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=SimpleNamespace(success=True)
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=f'["{_CHILD_REF}"]\t{_IMAGE_ID}\tlinux/arm64\n',
                stderr="",
            ),
        ]
    )

    result = backend._prepare_spawn_images(_spec())

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Spawn image platform incompatible for provision.node.orborus/worker."
    )


def test_online_child_image_is_pulled_and_verified_by_exact_reference(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    assert backend._prepare_spawn_images(_spec()) is None
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert commands[1] == ["docker", "pull", _CHILD_REF]
    assert commands[2][-1] == _CHILD_REF
    assert backend._run.call_args_list[1].kwargs["timeout"] == 600
    assert backend._run.call_args_list[2].kwargs["timeout"] == 600


def test_arm64_variant_image_matches_daemon_native_variant(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/arm64\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=f'["{_CHILD_REF}"]\t{_IMAGE_ID}\tlinux/arm64/v8\n',
                stderr="",
            ),
        ]
    )

    assert backend._prepare_spawn_images(_spec()) is None


def test_child_image_cache_alias_is_not_exact_identity_evidence(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    f'["ghcr.io/example/alias@{_DIGEST}"]\t{_IMAGE_ID}\tlinux/amd64\n'
                ),
                stderr="",
            ),
        ]
    )

    result = backend._prepare_spawn_images(_spec())

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Spawn image identity unavailable for provision.node.orborus/worker."
    )


def test_post_start_authority_is_observed_on_same_daemon(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        return_value={
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                }
            ],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": False},
        }
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    assert backend._verify_runtime_orchestration(_spec()) is None


def test_post_start_authority_rejects_image_default_endpoint_override(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        return_value={
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                }
            ],
            "Config": {"Env": ["DOCKER_HOST=tcp://docker.example:2375"]},
            "HostConfig": {"Privileged": False},
        }
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    result = backend._verify_runtime_orchestration(_spec())

    assert result is not None
    assert result.success is False
    assert result.error == "Docker authority runtime observation failed for orborus."


def test_post_start_authority_rejects_undeclared_extra_bind(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        return_value={
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                },
                {
                    "Type": "bind",
                    "Source": "/var/run",
                    "Destination": "/host",
                    "RW": True,
                },
            ],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": False},
        }
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    result = backend._verify_runtime_orchestration(_spec())

    assert result is not None
    assert result.success is False


def test_post_start_rejects_socket_propagation_to_another_service(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    socket_mount = {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "RW": True,
    }
    clean = {
        "Mounts": [socket_mount],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    propagated = {"Mounts": [socket_mount], "Config": {"Env": []}}
    backend.container_inspect = MagicMock(side_effect=[clean, propagated])
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )
    other = DeploymentNodeRealization(
        address="provision.node.worker",
        name="worker",
        service_name="worker",
        container_name="aptl-worker",
        networks=(),
    )
    spec = replace(_spec(), nodes=(*_spec().nodes, other))

    result = backend._verify_runtime_orchestration(spec)

    assert result is not None
    assert result.success is False
    assert result.error == "Docker authority propagated to unauthorized service worker."


@pytest.mark.parametrize(
    "child_exposure",
    [
        {
            "Created": "2025-01-01T00:01:00Z",
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                }
            ],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": False},
        },
        {
            "Created": "2025-01-01T00:01:00Z",
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/run",
                    "Destination": "/host-run",
                    "RW": True,
                }
            ],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": False},
        },
        {
            "Created": "2025-01-01T00:01:00Z",
            "Mounts": [],
            "Config": {"Env": ["DOCKER_HOST=tcp://docker.example:2375"]},
            "HostConfig": {"Privileged": False},
        },
        {
            "Created": "2025-01-01T00:01:00Z",
            "Mounts": [],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": True},
        },
    ],
)
def test_post_start_rejects_every_spawned_child_docker_authority(
    tmp_path, child_exposure: dict
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    holder = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    child_exposure["Config"]["Labels"] = {"org.aptl.authority": "worker-runtime"}
    child_exposure["Image"] = _IMAGE_ID
    backend.container_inspect = MagicMock(side_effect=[holder, child_exposure])
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="spawned-child-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Docker authority propagated to spawned child provision.node.orborus/worker."
    )
    assert backend._run.call_args_list[0].kwargs["timeout"] == 600
    assert backend._run.call_args_list[0].args[0] == [
        "docker",
        "ps",
        "-aq",
        "--filter",
        f"ancestor={_CHILD_REF}",
        "--filter",
        "label=org.aptl.authority=worker-runtime",
    ]


def test_post_start_rejects_descendant_image_selected_by_ancestor_filter(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    holder = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    child = {
        "Image": "sha256:" + "c" * 64,
        "Mounts": [],
        "Config": {
            "Env": [],
            "Labels": {"org.aptl.authority": "worker-runtime"},
        },
        "HostConfig": {"Privileged": False},
        "State": {"Running": False},
    }
    backend.container_inspect = MagicMock(side_effect=[holder, child])
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess(
                [], 0, stdout="descendant-child-id\n", stderr=""
            ),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Spawned-child image identity mismatch for provision.node.orborus/worker."
    )


def test_post_work_attestation_terminates_overdue_spawned_child(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    holder = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    child_running = {
        "Image": _IMAGE_ID,
        "Mounts": [],
        "Config": {
            "Env": [],
            "Labels": {"org.aptl.authority": "worker-runtime"},
        },
        "HostConfig": {"Privileged": False},
        "State": {"Running": True, "StartedAt": "2020-01-01T00:00:00Z"},
    }
    child_stopped = {"State": {"Running": False}}
    backend.container_inspect = MagicMock(
        side_effect=[holder, child_running, child_stopped]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="spawned-child-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
            subprocess.CompletedProcess([], 0, stdout="spawned-child-id\n", stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Spawned child exceeded lifecycle deadline for provision.node.orborus/worker."
    )
    assert backend._run.call_args_list[2].args[0] == [
        "docker",
        "stop",
        "--time",
        "10",
        "spawned-child-id",
    ]


def test_startup_child_attestation_uses_exact_label_and_allows_not_yet_spawned(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    socket_mount = {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "RW": True,
    }
    holder = {
        "Mounts": [socket_mount],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    backend.container_inspect = MagicMock(return_value=holder)
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    assert backend._verify_runtime_orchestration(_spec()) is None
    assert backend._run.call_args.args[0] == [
        "docker",
        "ps",
        "-aq",
        "--filter",
        f"ancestor={_CHILD_REF}",
        "--filter",
        "label=org.aptl.authority=worker-runtime",
    ]


def test_post_work_attestation_requires_exact_correlated_child_count(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        return_value={
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                }
            ],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": False},
        }
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.success is False
    assert result.error == (
        "Spawned-child correlation count mismatch for provision.node.orborus/worker."
    )


def test_running_child_is_supervised_until_terminal_before_success(
    tmp_path, monkeypatch
) -> None:
    from aptl.core.deployment import _compose_child_lifecycle as child_lifecycle

    backend = DockerComposeBackend(tmp_path)
    inspected = MagicMock(return_value={"State": {"Running": False}})
    backend.container_inspect = inspected
    monkeypatch.setattr(child_lifecycle.time, "sleep", lambda _seconds: None)
    started = datetime.now(timezone.utc).isoformat()

    result = backend._enforce_spawned_child_deadline(
        "spawned-child-id",
        {"State": {"Running": True, "StartedAt": started}},
        timeout=600,
        node_address="provision.node.orborus",
        template_id="worker",
    )

    assert result is None
    inspected.assert_called_once_with("spawned-child-id")
