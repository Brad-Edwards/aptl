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
    docker_authority_admissions as deployment_docker_authority_admissions,
    deployment_spawn_image_requirements,
    effective_orchestration_model_errors,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment._docker_image_identity import EXACT_IMAGE_INSPECT_FORMAT
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentPublishedPort,
    DeploymentRealizationSpec,
    DeploymentServicePort,
)
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DeploymentSpawnImageRequirement,
)


@pytest.fixture(autouse=True)
def _isolate_docker_endpoint_env(monkeypatch):
    """Keep endpoint-binding tests independent of the runner's ambient env.

    The local Docker endpoint now resolves from ``DOCKER_HOST`` (defaulting to
    ``/var/run/docker.sock`` when unset); clear it so a value in the developer's
    or CI runner's shell cannot change what these tests bind. Tests that
    exercise a specific ``DOCKER_HOST`` set it explicitly after this runs.
    """

    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)


_DIGEST = "sha256:" + "a" * 64
_CHILD_REF = f"ghcr.io/example/worker@{_DIGEST}"
_IMAGE_ID = "sha256:" + "b" * 64
_CHILD_INSPECT = f'["{_CHILD_REF}"]\t{_IMAGE_ID}\tlinux/amd64\n'


#: The admitted host-root-equivalent socket is exposed exactly as authored.
_DOCKER_SOCKET = "/var/run/docker.sock"


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


def test_same_node_authority_join_and_template_images_are_preserved() -> None:
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
            tag_reference="",
        ),
    )


def test_omitted_host_source_uses_the_admitted_local_docker_endpoint() -> None:
    runtime = _runtime().model_copy(deep=True)
    runtime.local_control_interfaces[0].bind_source = ""

    node = _spec(runtime).nodes[0]
    admission = admit_docker_authorities((node,))[0]

    assert admission.endpoint_source == "/var/run/docker.sock"
    assert admission.endpoint_target == "/var/run/docker.sock"


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


def test_a_template_without_children_still_names_its_image() -> None:
    """An undeclared observation contract is not an ungated authority.

    RAES defines a realized child as "an observed, realized child workload
    spawned by the authority", and the field defaults to empty, so demanding
    the correlation at plan time asks for runtime observation before anything
    has run. The images are a different matter: an authority holding the host
    socket may only launch what the pack pinned by digest, and dropping the
    requirement entirely left everything launched through that socket
    ungated (issue #912).

    So a template without a declared child still yields a requirement -- the
    image is pinned and pre-staged -- and carries no label or count, because
    those are the parts the pack genuinely did not declare.
    """

    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0]["realized_children"] = []
    runtime = RuntimeConfiguration.model_validate(payload)

    requirements = spawn_image_requirements(
        runtime, node_address="provision.node.orborus"
    )

    assert len(requirements) == 1
    requirement = requirements[0]
    assert "@sha256:" in requirement.image_ref
    assert requirement.execution_timeout_seconds > 0
    assert requirement.tag_reference == ""


def test_an_authority_with_neither_templates_nor_children_is_not_gated() -> None:
    """Privilege stated for transparency alone declares nothing to prepare."""

    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0]["realized_children"] = []
    payload["orchestration_authorities"][0]["spawn_templates"] = []
    runtime = RuntimeConfiguration.model_validate(payload)

    assert (
        spawn_image_requirements(runtime, node_address="provision.node.orborus") == ()
    )


def test_an_authority_without_children_is_still_admitted_with_its_controls() -> None:
    """No child contract removes the count, never the privilege controls.

    The authority still holds the host Docker socket, so the admission and every
    mount and access control on it must survive, and so must the digest-pinned
    child-image preparation. Only the post-start child count goes away, because
    nothing declared it.
    """

    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0]["realized_children"] = []
    node = replace(
        _spec().nodes[0], runtime=RuntimeConfiguration.model_validate(payload)
    )

    admissions = admit_docker_authorities((node,))

    assert len(admissions) == 1
    admission = admissions[0]
    # The pre-pull survives -- it is the gate on what the socket can launch --
    # while the post-start child count goes away, because nothing declared it.
    assert len(admission.spawn_requirements) == 1
    assert admission.spawn_requirements[0].image_ref == _CHILD_REF
    assert admission.endpoint_target == "/var/run/docker.sock"
    assert admission.endpoint_read_write is True
    assert admission.privilege_class == "host_root_equivalent"


def test_the_backend_accepts_an_admission_with_no_realized_children() -> None:
    """The backend-side integrity check makes the same allowance.

    `docker_authority_admissions` re-validates the carried decision before
    lowering Compose. It required every admission to carry a child contract,
    which rejected exactly the authorities that declare privilege without an
    expected child inventory -- so the plan-time fix alone still failed the boot
    with `runtime-authority-admission-invalid`. Contracts that *are* carried are
    still checked in full.
    """

    payload = _runtime().model_dump(mode="json")
    payload["orchestration_authorities"][0]["realized_children"] = []
    node = replace(
        _spec().nodes[0], runtime=RuntimeConfiguration.model_validate(payload)
    )
    spec = replace(
        _spec(),
        nodes=(node,),
        docker_authority_admissions=admit_docker_authorities((node,)),
    )

    admissions = deployment_docker_authority_admissions(spec)

    assert len(admissions) == 1
    requirements = deployment_spawn_image_requirements(spec)
    assert len(requirements) == 1
    assert requirements[0].tag_reference == ""
    assert "@sha256:" in requirements[0].image_ref


def _ports_backend(tmp_path, listed, inspected):
    """A backend whose `docker ps` / `docker inspect` return canned output."""

    backend = DockerComposeBackend(tmp_path)
    calls: list[list[str]] = []

    def _run(cmd, *, timeout=None):
        calls.append(cmd)
        return listed if cmd[1] == "ps" else inspected

    backend._run = _run
    return backend, calls


def _completed(returncode=0, stdout=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def test_owned_host_ports_are_read_from_this_project_only(tmp_path) -> None:
    """The query is scoped to the compose project and parses real inspect output.

    Ports held by this project's own containers are not conflicts: the retry
    path re-applies the plan with the range still up, and Compose reconciles
    those containers. A port probe cannot tell them from a stranger's, so the
    backend asks Docker which ones are its own.
    """

    inspect_output = (
        '{"443/tcp":[{"HostIp":"127.0.0.1","HostPort":"8443"}],'
        '"9200/tcp":[{"HostIp":"127.0.0.1","HostPort":"9200"}]}\n'
        '{"53/udp":[{"HostIp":"127.0.0.1","HostPort":"5353"}]}\n'
    )
    backend, calls = _ports_backend(
        tmp_path,
        _completed(stdout="abc123\ndef456\n"),
        _completed(stdout=inspect_output),
    )

    owned = backend._published_host_ports()

    assert owned == frozenset(
        {
            ("127.0.0.1", 8443, "tcp"),
            ("127.0.0.1", 9200, "tcp"),
            ("127.0.0.1", 5353, "udp"),
        }
    )
    # Scoped to this compose project, never every container on the host.
    assert any(
        f"label=com.docker.compose.project={backend._project_name}" in part
        for part in calls[0]
    )
    assert calls[1][:2] == ["docker", "inspect"]
    assert calls[1][-2:] == ["abc123", "def456"]


def test_an_all_interfaces_publish_satisfies_a_loopback_declaration(tmp_path) -> None:
    """Docker reports an all-interfaces bind with an empty or 0.0.0.0 host IP.

    A scenario declaring `127.0.0.1` is satisfied by a container already
    published on every interface, so that binding must be recognised as ours
    rather than read as a foreign holder of the loopback port.
    """

    backend, _ = _ports_backend(
        tmp_path,
        _completed(stdout="abc123\n"),
        _completed(stdout='{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}\n'),
    )

    assert ("127.0.0.1", 8080, "tcp") in backend._published_host_ports()


@pytest.mark.parametrize(
    ("listed", "inspected"),
    [
        (_completed(returncode=1), _completed()),
        (_completed(stdout=""), _completed()),
        (_completed(stdout="abc123\n"), _completed(returncode=1)),
        (_completed(stdout="abc123\n"), _completed(stdout="not json\n")),
        (_completed(stdout="abc123\n"), _completed(stdout='{"80/tcp":null}\n')),
        (_completed(stdout="abc123\n"), _completed(stdout="\n\n")),
        (_completed(stdout="abc123\n"), _completed(stdout='["not","a","map"]\n')),
        (
            _completed(stdout="abc123\n"),
            _completed(
                stdout='{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"nope"}]}\n'
            ),
        ),
    ],
)
def test_unreadable_docker_state_yields_no_owned_ports(tmp_path, listed, inspected):
    """Unreadable state falls back to the probe alone, never to a false claim.

    Claiming a port is ours on bad evidence would suppress a real conflict, so
    every failure path returns nothing and the stricter probe-only behaviour
    stands.
    """

    backend, _ = _ports_backend(tmp_path, listed, inspected)

    assert backend._published_host_ports() == frozenset()


def test_a_foreign_holder_of_a_declared_port_still_refuses_the_start(tmp_path) -> None:
    """Ownership narrows the check; it does not disable it.

    A declared binding held by something outside this project is still the
    fail-closed conflict it always was, reported rather than published
    elsewhere.
    """

    node = DeploymentNodeRealization(
        address="provision.node.web",
        name="web",
        service_name="web",
        container_name="aptl-web",
        networks=(),
        published_ports=(DeploymentPublishedPort(container_port=80, host_port=8099),),
    )
    spec = DeploymentRealizationSpec(profiles=(), nodes=(node,), networks=(), images=())
    backend = DockerComposeBackend(tmp_path)
    # Nothing of ours publishes it, and the probe finds it taken.
    backend._run = lambda cmd, *, timeout=None: _completed()
    monkey = pytest.MonkeyPatch()
    monkey.setattr(
        "aptl.core.deployment._compose_port_realization.port_available",
        lambda *_a, **_k: False,
    )
    try:
        failure = backend._realize_published_ports(spec)
    finally:
        monkey.undo()

    assert failure is not None
    assert failure.success is False
    assert "already in use" in failure.error


def test_a_raising_docker_query_does_not_break_the_start(tmp_path) -> None:
    """A daemon that errors must not crash realization."""

    backend = DockerComposeBackend(tmp_path)

    def _boom(cmd, *, timeout=None):
        raise OSError("docker daemon unreachable")

    backend._run = _boom

    assert backend._published_host_ports() == frozenset()


def test_ports_are_not_queried_when_nothing_declares_an_exact_binding(
    tmp_path,
) -> None:
    """No declared host port means no reason to ask Docker anything."""

    backend = DockerComposeBackend(tmp_path)
    queried: list[list[str]] = []
    backend._run = lambda cmd, *, timeout=None: queried.append(cmd) or _completed()

    assert backend._realize_published_ports(_spec()) is None
    assert queried == []


def test_graph_admission_preserves_participant_profile_authority_holder() -> None:
    holder = replace(_spec().nodes[0], profiles=("kali",))

    admissions = admit_docker_authorities((holder,))

    assert len(admissions) == 1
    assert admissions[0].node_address == holder.address


def test_graph_admission_preserves_serving_holder_on_shared_network() -> None:
    holder = replace(
        _spec().nodes[0],
        services=(DeploymentServicePort(name="participant-api", port=8080),),
    )

    admissions = admit_docker_authorities((holder,))

    assert len(admissions) == 1
    assert holder.networks == ("security-net",)
    assert admissions[0].node_address == holder.address


def test_effective_model_rejects_missing_graph_admission() -> None:
    payload = {
        "services": {
            "orborus": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": _DOCKER_SOCKET,
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
    bundle = SimpleNamespace(
        sdl_path=tmp_path / "scenario.yaml",
        root=tmp_path,
        pack_identity=None,
    )
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
        raes.admit_raes_scenario(tmp_path, config, backend)

    assert calls == ["bind", "availability"]


def test_generated_compose_lowers_the_declared_host_root_socket(tmp_path) -> None:
    """The admitted host-root-equivalent holder gets the exact Docker socket."""

    from aptl.core.deployment._compose_node_generation import render_realization_compose

    service = render_realization_compose(_spec())["services"]["orborus"]

    assert service["volumes"] == [
        {
            "type": "bind",
            "source": _DOCKER_SOCKET,
            "target": "/var/run/docker.sock",
            "read_only": False,
        }
    ]
    assert service.get("privileged") is not True


def test_generated_compose_preserves_existing_volumes_when_adding_socket(
    monkeypatch, tmp_path
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
            "source": _DOCKER_SOCKET,
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


def test_spawned_child_contract_allows_declared_authority_on_shared_daemon(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend.bind_local_docker_socket = MagicMock(return_value=LabResult(success=True))
    backend._run = MagicMock()

    result = backend._runtime_orchestration_preflight(_spec())

    assert result is None
    backend.bind_local_docker_socket.assert_called_once()
    backend._run.assert_not_called()


def test_verified_appliance_guest_daemon_admits_runtime_spawned_children(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend._docker_socket_identity = (1, 2)
    backend._docker_socket_path = "/var/run/docker.sock"
    backend._docker_daemon_id = "guest-daemon"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.configure_appliance_boundary(
        MagicMock(),
        SimpleNamespace(
            guest_daemon_id="guest-daemon",
            boundary_helper_image="example.test/helper:fixed",
        ),
        isolated_daemon=True,
    )

    assert backend._runtime_orchestration_preflight(_spec()) is None
    backend.revalidate_local_docker_socket.assert_called_once()


@pytest.mark.parametrize("mismatch", ["unbound", "wrong-daemon", "remote-socket"])
def test_appliance_guest_isolation_rejects_unbound_or_redirected_daemon(
    tmp_path,
    mismatch,
) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend._docker_socket_identity = None if mismatch == "unbound" else (1, 2)
    backend._docker_socket_path = (
        "/run/user/1000/docker.sock"
        if mismatch == "remote-socket"
        else "/var/run/docker.sock"
    )
    backend._docker_daemon_id = (
        "other-daemon" if mismatch == "wrong-daemon" else "guest-daemon"
    )
    policy = MagicMock()
    binding = SimpleNamespace(
        guest_daemon_id="guest-daemon",
        boundary_helper_image="example.test/helper:fixed",
    )
    with pytest.raises(ValueError, match="isolated guest Docker daemon"):
        backend.configure_appliance_boundary(
            policy,
            binding,
            isolated_daemon=True,
        )
    assert not getattr(backend, "_attempt_isolated_docker_daemon", False)


def test_effective_compose_rejects_duplicate_or_endpoint_redirects() -> None:
    mount = {
        "type": "bind",
        "source": _DOCKER_SOCKET,
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


def test_effective_compose_preserves_privileged_authority_holder() -> None:
    render_payload = {
        "services": {
            "orborus": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": _DOCKER_SOCKET,
                        "target": "/var/run/docker.sock",
                        "read_only": False,
                    }
                ],
                "privileged": True,
            }
        }
    }

    assert effective_orchestration_model_errors(render_payload, _spec()) == []


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
                        "source": _DOCKER_SOCKET,
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
                        "source": _DOCKER_SOCKET,
                        "target": "/var/run/docker.sock",
                    }
                ]
            },
        }
    }

    assert effective_orchestration_model_errors(payload, _spec()) == []


def test_an_admitted_authority_admits_only_its_exact_host_socket_mount() -> None:
    """The declared host socket is admitted, but no other route is."""

    runtime = _runtime()
    host_socket = {
        "Type": "bind",
        "Source": _DOCKER_SOCKET,
        "Destination": "/var/run/docker.sock",
        "RW": True,
    }
    substitute = {**host_socket, "Source": "/tmp/other-docker.sock"}

    # Without an admission, neither is allowed.
    assert _has_undeclared_mounts([host_socket], [], runtime)
    assert _has_undeclared_mounts([substitute], [], runtime)

    # With one, only the exact host-root-equivalent grant is admitted.
    assert not _has_undeclared_mounts(
        [host_socket], [], runtime, docker_authority_admitted=True
    )
    assert _has_undeclared_mounts(
        [substitute], [], runtime, docker_authority_admitted=True
    )

    # An admitted authority still admits nothing else alongside it.
    assert _has_undeclared_mounts(
        [host_socket, {"Type": "bind", "Destination": "/host", "RW": True}],
        [],
        runtime,
        docker_authority_admitted=True,
    )
    assert _has_undeclared_mounts(
        [{**host_socket, "Destination": "/tmp/docker.sock"}],
        [],
        runtime,
        docker_authority_admitted=True,
    )
    assert _has_undeclared_mounts(
        [{**host_socket, "RW": False}],
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
                "Source": _DOCKER_SOCKET,
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


def test_authority_attestation_survives_a_holder_without_a_docker_cli(
    tmp_path,
) -> None:
    """A socket holder is not required to ship the Docker CLI.

    The in-container `docker info` probe corroborates that the holder's socket
    reaches the admitted daemon. Real holders talk to the socket over the Docker
    API and ship no CLI at all -- Shuffle's orborus is one, so every TechVault
    boot failed attestation with exit 127, "executable file not found".

    The boundary itself is established host-side and still is: the mount is
    exactly the admitted socket, there is no endpoint override, and the holder is
    unprivileged. An absent CLI leaves nothing to corroborate; a CLI that answers
    for a *different* daemon is still a failure.
    """

    spec = _spec()
    admission = spec.docker_authority_admissions[0]
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.container_inspect = MagicMock(
        return_value={
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": _DOCKER_SOCKET,
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                }
            ],
            "Config": {"Env": []},
            "HostConfig": {"Privileged": False},
        }
    )

    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess(
            [], 127, stdout="", stderr='exec: "docker": executable file not found'
        )
    )
    assert backend._runtime_authority_matches("aptl-orborus", admission)

    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-b\n", stderr="")
    )
    assert not backend._runtime_authority_matches("aptl-orborus", admission)


def test_local_backend_defaults_to_system_socket_without_docker_host(
    tmp_path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path)
    socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=42)
    monkeypatch.setattr(os, "lstat", lambda _path: socket_stat)
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
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


def test_local_backend_honors_unix_docker_host_for_rootless(
    tmp_path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path)
    rootless_host = "unix:///run/user/1234/docker.sock"
    socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=7, st_ino=11)
    seen: dict[str, str] = {}

    def _lstat(path):
        seen["lstat"] = path
        return socket_stat

    monkeypatch.setattr(os, "lstat", _lstat)
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    monkeypatch.setenv("DOCKER_HOST", rootless_host)
    monkeypatch.setenv("DOCKER_CONTEXT", "rootless")
    run = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-r\n", stderr="")
    )
    monkeypatch.setattr("subprocess.run", run)

    result = backend.bind_local_docker_socket()

    assert result.success is True
    # The rootless socket path is what gets stat'd and driven, not the default.
    assert seen["lstat"] == "/run/user/1234/docker.sock"
    kwargs = run.call_args.kwargs
    assert kwargs["env"]["DOCKER_HOST"] == rootless_host
    assert "DOCKER_CONTEXT" not in kwargs["env"]
    assert backend.revalidate_local_docker_socket().success is True


def test_local_backend_rejects_non_unix_docker_host(tmp_path, monkeypatch) -> None:
    backend = DockerComposeBackend(tmp_path)
    monkeypatch.setattr(os, "lstat", lambda _path: pytest.fail("must not stat"))
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example:2375")

    result = backend.bind_local_docker_socket()

    assert result.success is False
    assert result.error == (
        "Docker control authority requires a local unix:// socket; "
        "DOCKER_HOST does not name one."
    )


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
    # Docker omits Variant for images without an architecture variant. A
    # direct .Variant lookup makes the entire inspect command fail on amd64.
    assert '{{with index . "Variant"}}/{{.}}{{end}}' in commands[2][4]
    assert commands[2][4] == EXACT_IMAGE_INSPECT_FORMAT
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
                    "Source": _DOCKER_SOCKET,
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
                    "Source": _DOCKER_SOCKET,
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
                    "Source": _DOCKER_SOCKET,
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
    holder_mount = {
        "Type": "bind",
        "Source": _DOCKER_SOCKET,
        "Destination": "/var/run/docker.sock",
        "RW": True,
    }
    clean = {
        "Mounts": [holder_mount],
        "Config": {"Env": []},
        "HostConfig": {"Privileged": False},
    }
    # A service that is not the admitted holder carries a socket route at all:
    # whether it is the host's own or the mediated one, it was not granted.
    propagated = {"Mounts": [holder_mount], "Config": {"Env": []}}
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


def test_authored_privilege_alone_is_not_docker_control_authority(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)

    assert not backend._inspected_container_has_docker_authority(
        {"HostConfig": {"Privileged": True}, "Mounts": [], "Config": {"Env": []}}
    )


def _authority_runtime(**authority: object) -> RuntimeConfiguration:
    """Build a runtime whose single authority carries exactly what is given."""

    return RuntimeConfiguration.model_validate(
        {
            "local_control_interfaces": [
                {
                    "control_interface_id": "docker-sock",
                    "path": "/var/run/docker.sock",
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
                    "lifecycle_policy": {"execution_timeout": "600"},
                    **authority,
                }
            ],
        }
    )


def test_tag_only_image_reference_is_realized_as_written() -> None:
    # RuntimeOrchestrationSpawnTemplate.image_ref has no pattern in
    # sdl-authoring-input-v1.json. A tag is what the author chose to write.
    runtime = _authority_runtime(
        spawn_templates=[
            {"template_id": "app", "image_ref": "frikky/shuffle:http_1.4.0"}
        ]
    )

    requirements = spawn_image_requirements(
        runtime, node_address="provision.node.orborus"
    )

    assert [item.image_ref for item in requirements] == ["frikky/shuffle:http_1.4.0"]


def test_template_without_an_image_yields_nothing_to_fetch() -> None:
    # image_ref defaults to "" and only template_id is required, so a template
    # naming a purpose alone is legal and has no image to realize.
    runtime = _authority_runtime(
        spawn_templates=[{"template_id": "worker", "purpose": "workflow execution"}]
    )

    assert spawn_image_requirements(runtime, node_address="provision.node.orborus") == ()


def test_realized_child_carrying_only_its_workload_id_is_accepted() -> None:
    # workload_id is the only required property; evidence_ref and count are
    # optional and RAES constrains neither to APTL's label or range.
    runtime = _authority_runtime(
        spawn_templates=[{"template_id": "worker", "image_ref": _CHILD_REF}],
        realized_children=[{"workload_id": "worker-instance"}],
    )

    requirements = spawn_image_requirements(
        runtime, node_address="provision.node.orborus"
    )

    assert [item.image_ref for item in requirements] == [_CHILD_REF]


def test_realized_children_without_spawn_templates_are_accepted() -> None:
    runtime = _authority_runtime(
        realized_children=[{"workload_id": "worker-instance", "count": 0}]
    )

    assert spawn_image_requirements(runtime, node_address="provision.node.orborus") == ()


def test_tag_and_digest_reference_carries_the_authored_tag() -> None:
    reference = f"frikky/shuffle:http_1.4.0@{_DIGEST}"
    runtime = _authority_runtime(
        spawn_templates=[{"template_id": "app", "image_ref": reference}]
    )

    requirement = spawn_image_requirements(
        runtime, node_address="provision.node.orborus"
    )[0]

    assert requirement.image_ref == reference
    assert requirement.tag_reference == "frikky/shuffle:http_1.4.0"


_TAGGED_REF = f"frikky/shuffle:http_1.4.0@{_DIGEST}"
_TAGGED_TAG = "frikky/shuffle:http_1.4.0"
_TAGGED_INSPECT = f'["frikky/shuffle@{_DIGEST}"]\t{_IMAGE_ID}\tlinux/amd64\n'
_OTHER_IMAGE_ID = "sha256:" + "c" * 64


def _tagged_backend(tmp_path, *alias_results):
    """Offline backend whose platform and exact inspect already succeed."""

    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_TAGGED_INSPECT, stderr=""),
            *alias_results,
        ]
    )
    return backend


def _commands(backend):
    return [call.args[0] for call in backend._run.call_args_list]


def test_absent_authored_tag_is_created_from_the_verified_image(tmp_path) -> None:
    backend = _tagged_backend(
        tmp_path,
        subprocess.CompletedProcess(
            [], 1, stdout="", stderr="Error: No such image: frikky/shuffle:http_1.4.0\n"
        ),
        subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        subprocess.CompletedProcess([], 0, stdout=f"{_IMAGE_ID}\n", stderr=""),
    )

    assert backend._prepare_spawn_images(_spec(_runtime(image_ref=_TAGGED_REF))) is None
    commands = _commands(backend)
    assert ["docker", "tag", _TAGGED_REF, _TAGGED_TAG] in commands
    assert all("pull" not in command for command in commands)
    assert all("manifest" not in command for command in commands)
    assert all("build" not in command for command in commands)


def test_authored_tag_pointing_elsewhere_is_repointed_and_reverified(tmp_path) -> None:
    backend = _tagged_backend(
        tmp_path,
        subprocess.CompletedProcess([], 0, stdout=f"{_OTHER_IMAGE_ID}\n", stderr=""),
        subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        subprocess.CompletedProcess([], 0, stdout=f"{_IMAGE_ID}\n", stderr=""),
    )

    assert backend._prepare_spawn_images(_spec(_runtime(image_ref=_TAGGED_REF))) is None
    assert ["docker", "tag", _TAGGED_REF, _TAGGED_TAG] in _commands(backend)


def test_indeterminate_tag_read_fails_without_tagging(tmp_path) -> None:
    # A daemon, permission, or timeout failure is not proof the name is absent,
    # so it must never authorize mutating shared daemon state.
    backend = _tagged_backend(
        tmp_path,
        subprocess.CompletedProcess(
            [], 1, stdout="", stderr="Cannot connect to the Docker daemon\n"
        ),
    )

    result = backend._prepare_spawn_images(_spec(_runtime(image_ref=_TAGGED_REF)))

    assert result is not None
    assert result.success is False
    assert all(command[:2] != ["docker", "tag"] for command in _commands(backend))


def test_authored_tag_already_resolving_to_the_image_is_left_alone(tmp_path) -> None:
    backend = _tagged_backend(
        tmp_path,
        subprocess.CompletedProcess([], 0, stdout=f"{_IMAGE_ID}\n", stderr=""),
    )

    assert backend._prepare_spawn_images(_spec(_runtime(image_ref=_TAGGED_REF))) is None
    assert all(command[:2] != ["docker", "tag"] for command in _commands(backend))


def test_conflicting_authored_tags_fail_before_any_tagging(tmp_path) -> None:
    # Two templates naming the same repository:tag with different digests
    # cannot both be satisfied: one local name cannot resolve to two images.
    other_digest = "sha256:" + "d" * 64
    runtime = _authority_runtime(
        spawn_templates=[
            {"template_id": "app-a", "image_ref": _TAGGED_REF},
            {
                "template_id": "app-b",
                "image_ref": f"frikky/shuffle:http_1.4.0@{other_digest}",
            },
        ]
    )
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend._run = MagicMock()

    result = backend._prepare_spawn_images(_spec(runtime))

    assert result is not None
    assert result.success is False
    assert "frikky/shuffle:http_1.4.0" in result.error
    # A contradiction in what was authored needs no daemon to detect.
    backend._run.assert_not_called()
