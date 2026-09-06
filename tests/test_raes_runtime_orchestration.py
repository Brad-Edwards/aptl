"""Runtime-orchestration authority lowering and image-closure guards (#949)."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
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
from aptl.core.deployment._docker_image_identity import (
    EXACT_IMAGE_INSPECT_FORMAT,
    exact_inspected_image_identity,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.config import AptlConfig
from aptl.core.operator_policy import OperatorPolicy, load_operator_policy
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    DeploymentServicePort,
)
from aptl.core.lab_types import LabResult
from aptl.core.scenario_bundle import PackIdentity
from aptl.runtime_authority import (
    DeploymentSpawnImageRequirement,
)

_DIGEST = "sha256:" + "a" * 64
_WORKER_REF = f"ghcr.io/example/worker:latest@{_DIGEST}"
_APP_REF = f"registry.example:5000/nested/http:1.4.0@{_DIGEST}"
_IMAGE_ID = "sha256:" + "b" * 64
_CHILD_INSPECT = f'["{_WORKER_REF}"]\t{_IMAGE_ID}\tlinux/amd64\n'
_PACK_IDENTITY = PackIdentity(
    pack_id="techvault",
    pack_version="5.0.0",
    set_digest="sha256:" + "c" * 64,
)
_RUN_ID = "run-974"
_ATTEMPT_ID = "attempt-974"
_EXECUTION_ID = "shuffle-execution-974"


def test_exact_image_inspection_tolerates_a_missing_platform_variant() -> None:
    """Docker omits ``Variant`` for amd64; direct field access then errors."""

    assert '{{if index . "Variant"}}' in EXACT_IMAGE_INSPECT_FORMAT
    assert "{{if .Variant}}" not in EXACT_IMAGE_INSPECT_FORMAT


def test_exact_image_identity_accepts_docker_canonical_tagged_digest() -> None:
    """RepoDigests omits the redundant tag from a ``tag@digest`` pull."""

    image_ref = f"registry.example:5000/team/worker:1.4@{_DIGEST}"
    inspected = (
        f'["registry.example:5000/team/worker@{_DIGEST}"]\t{_IMAGE_ID}\tlinux/amd64\n'
    )

    identity = exact_inspected_image_identity(inspected, image_ref)

    assert identity is not None
    assert identity.image_id == _IMAGE_ID


def _authority_policy(
    *,
    image_template_ids: list[str] | None = None,
    delegated_template_ids: list[str] | None = None,
) -> OperatorPolicy:
    image_ids = ["worker"] if image_template_ids is None else image_template_ids
    delegated_ids = (
        ["worker"] if delegated_template_ids is None else delegated_template_ids
    )
    return OperatorPolicy(
        docker_authority_grants=[
            {
                "pack_id": _PACK_IDENTITY.pack_id,
                "pack_version": _PACK_IDENTITY.pack_version,
                "pack_set_digest": _PACK_IDENTITY.set_digest,
                "component_address": "provision.node.orborus",
                "authority_id": "worker-runtime",
                "endpoint_source": "/var/run/docker.sock",
                "image_template_ids": image_ids,
                "delegated_template_ids": delegated_ids,
            }
        ]
    )


def _admit(
    *nodes: DeploymentNodeRealization,
    policy: OperatorPolicy | None = None,
    pack_identity: PackIdentity = _PACK_IDENTITY,
):
    selected = policy or _authority_policy()
    return admit_docker_authorities(
        tuple(nodes),
        pack_identity=pack_identity,
        project_name="aptl",
        run_id=_RUN_ID,
        attempt_id=_ATTEMPT_ID,
        grants=tuple(selected.docker_authority_grants),
    )


def _runtime(
    *, image_ref: str = _WORKER_REF, include_app: bool = False
) -> RuntimeConfiguration:
    templates = [{"template_id": "worker", "image_ref": image_ref}]
    if include_app:
        templates.append({"template_id": "http-1-4-0", "image_ref": _APP_REF})
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
                    "spawn_templates": templates,
                    "lifecycle_policy": {"execution_timeout": "600"},
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
    template_ids = [
        template.template_id
        for authority in runtime.orchestration_authorities
        for template in authority.spawn_templates
    ]
    policy = _authority_policy(
        image_template_ids=template_ids,
        delegated_template_ids=["worker"],
    )
    return DeploymentRealizationSpec(
        profiles=("soc",),
        nodes=(node,),
        networks=(DeploymentNetworkRealization(name="security-net"),),
        docker_authority_admissions=tuple(
            admission.bind_product_execution(_EXECUTION_ID)
            for admission in _admit(node, policy=policy)
        ),
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
    runtime = _runtime(include_app=True)

    bindings = docker_control_authorities(
        runtime, node_address="provision.node.orborus"
    )
    requirements = spawn_image_requirements(
        runtime,
        node_address="provision.node.orborus",
        delegated_template_ids=frozenset({"worker"}),
    )

    assert len(bindings) == 1
    authority, interface = bindings[0]
    assert authority.control_interface_ref == interface.control_interface_id
    assert interface.bind_source == ""
    assert interface.path == "/var/run/docker.sock"
    assert requirements == (
        DeploymentSpawnImageRequirement(
            node_address="provision.node.orborus",
            authority_id="worker-runtime",
            template_id="worker",
            image_ref=_WORKER_REF,
            execution_timeout_seconds=600,
            runtime_alias="ghcr.io/example/worker:latest",
            delegated_docker_authority=True,
        ),
        DeploymentSpawnImageRequirement(
            node_address="provision.node.orborus",
            authority_id="worker-runtime",
            template_id="http-1-4-0",
            image_ref=_APP_REF,
            execution_timeout_seconds=600,
            runtime_alias="registry.example:5000/nested/http:1.4.0",
            delegated_docker_authority=False,
        ),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bind_source", "/var/run/docker.sock"),
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


def test_authored_realized_children_are_observations_not_admission_input() -> None:
    payload = _runtime(include_app=True).model_dump(mode="json")
    payload["orchestration_authorities"][0]["realized_children"] = [
        {
            "workload_id": "untrusted-observation",
            "image_ref": "mutable:latest",
            "count": 0,
            "evidence_ref": "untrusted",
        }
    ]
    runtime = RuntimeConfiguration.model_validate(payload)

    requirements = spawn_image_requirements(
        runtime,
        node_address="provision.node.orborus",
        delegated_template_ids=frozenset({"worker"}),
    )

    assert [item.template_id for item in requirements] == ["worker", "http-1-4-0"]


def test_graph_admission_requires_an_independent_operator_grant() -> None:
    holder = _spec().nodes[0]

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-operator-grant-missing"
    ):
        _admit(holder, policy=OperatorPolicy())


def test_graph_admission_rejects_a_stale_template_grant() -> None:
    holder = _spec().nodes[0]
    policy = _authority_policy(image_template_ids=["worker", "unexpected"])

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-operator-grant-invalid"
    ):
        _admit(holder, policy=policy)


def test_graph_admission_rejects_a_different_pack_identity() -> None:
    holder = _spec().nodes[0]
    other_pack = replace(_PACK_IDENTITY, pack_id="other-pack")

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-operator-grant-missing"
    ):
        _admit(holder, pack_identity=other_pack)


def test_graph_admission_rejects_same_pack_id_with_different_content() -> None:
    holder = _spec().nodes[0]
    changed_pack = replace(_PACK_IDENTITY, set_digest="sha256:" + "d" * 64)

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-operator-grant-missing"
    ):
        _admit(holder, pack_identity=changed_pack)


def test_graph_admission_requires_run_and_attempt_scope() -> None:
    holder = _spec().nodes[0]
    policy = _authority_policy()

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-execution-scope-missing"
    ):
        admit_docker_authorities(
            (holder,),
            pack_identity=_PACK_IDENTITY,
            project_name="aptl",
            grants=tuple(policy.docker_authority_grants),
        )


def test_operator_policy_rejects_delegation_outside_image_inventory() -> None:
    with pytest.raises(ValueError, match="delegated_template_ids"):
        _authority_policy(
            image_template_ids=["worker", "http-1-4-0"],
            delegated_template_ids=["unknown"],
        )


def test_operator_policy_rejects_duplicate_grant_keys() -> None:
    grant = {
        "pack_id": "techvault",
        "pack_version": _PACK_IDENTITY.pack_version,
        "pack_set_digest": _PACK_IDENTITY.set_digest,
        "component_address": "provision.node.orborus",
        "authority_id": "worker-runtime",
        "endpoint_source": "/var/run/docker.sock",
        "image_template_ids": ["worker"],
        "delegated_template_ids": ["worker"],
    }

    with pytest.raises(ValueError, match="Docker authority grants must be unique"):
        OperatorPolicy(docker_authority_grants=[grant, dict(grant)])


def test_absent_operator_policy_loads_as_deny_all(tmp_path) -> None:
    assert load_operator_policy(tmp_path).docker_authority_grants == ()


def test_malformed_operator_policy_is_rejected(tmp_path) -> None:
    (tmp_path / "operator-policy.json").write_text("not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="operator policy is not valid JSON"):
        load_operator_policy(tmp_path)


def test_operator_policy_symlink_is_rejected(tmp_path) -> None:
    target = tmp_path / "policy-target.json"
    target.write_text('{"schema_version":"aptl.operator-policy/v1"}', encoding="utf-8")
    (tmp_path / "operator-policy.json").symlink_to(target)

    with pytest.raises(ValueError, match="operator policy could not be read safely"):
        load_operator_policy(tmp_path)


def test_checked_in_operator_policy_grants_only_the_techvault_worker_template() -> None:
    policy = load_operator_policy(Path(__file__).resolve().parents[1])

    grant = policy.docker_authority_grants[0]
    assert grant.pack_id == "techvault"
    assert grant.pack_version == "0.1.0"
    assert grant.pack_set_digest.startswith("sha256:")
    assert grant.component_address == "provision.node.shuffle-orborus"
    assert grant.authority_id == "shuffle-orborus"
    assert grant.endpoint_source == "/var/run/docker.sock"
    assert grant.image_template_ids == (
        "shuffle-worker",
        "shuffle-http-1-4-0",
    )
    assert grant.delegated_template_ids == ("shuffle-worker",)


def test_graph_admission_carries_backend_owned_correlation_and_delegation() -> None:
    admission = _spec().docker_authority_admissions[0]

    assert admission.pack_id == "techvault"
    assert admission.run_id == _RUN_ID
    assert admission.attempt_id == _ATTEMPT_ID
    assert admission.product_execution_ids == (_EXECUTION_ID,)
    assert admission.correlation_id.startswith("sha256:")
    assert admission.endpoint_source == "/var/run/docker.sock"
    assert [
        item.template_id
        for item in admission.spawn_requirements
        if item.delegated_docker_authority
    ] == ["worker"]


def test_multiple_matching_operator_grants_are_rejected() -> None:
    holder = _spec().nodes[0]
    first = _authority_policy().docker_authority_grants[0]
    duplicated = first.model_copy(update={"image_template_ids": ["worker"]})
    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-operator-grant-invalid"
    ):
        admit_docker_authorities(
            (holder,),
            pack_identity=_PACK_IDENTITY,
            project_name="aptl",
            run_id=_RUN_ID,
            attempt_id=_ATTEMPT_ID,
            grants=(first, duplicated),
        )


def test_graph_admission_rejects_participant_profile_authority_holder() -> None:
    holder = replace(_spec().nodes[0], profiles=("kali",))

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-not-management-only"
    ):
        _admit(holder)


def test_graph_admission_rejects_participant_serving_authority_holder() -> None:
    holder = replace(
        _spec().nodes[0],
        services=(DeploymentServicePort(name="participant-api", port=8080),),
    )

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-not-management-only"
    ):
        _admit(holder)


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


@pytest.mark.parametrize(
    "field,value",
    [
        ("pack_set_digest", "sha256:short"),
        ("correlation_id", "sha256:short"),
        ("product_execution_ids", ("invalid/execution",)),
    ],
)
def test_core_rejects_malformed_carried_admission_identity(field, value) -> None:
    spec = _spec()
    admission = replace(spec.docker_authority_admissions[0], **{field: value})

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-admission-invalid"
    ):
        deployment_spawn_image_requirements(
            replace(spec, docker_authority_admissions=(admission,))
        )


def test_core_rejects_mutable_image_in_carried_admission() -> None:
    spec = _spec()
    admission = spec.docker_authority_admissions[0]
    requirement = replace(
        admission.spawn_requirements[0],
        image_ref="ghcr.io/example/worker:latest",
        runtime_alias="ghcr.io/example/worker:latest",
    )

    with pytest.raises(
        ValueError, match="aptl.provisioner.runtime-authority-admission-invalid"
    ):
        deployment_spawn_image_requirements(
            replace(
                spec,
                docker_authority_admissions=(
                    replace(admission, spawn_requirements=(requirement,)),
                ),
            )
        )


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

    policy = _authority_policy()
    result = prepare_runtime_orchestration_for_scenario(
        scenario,
        backend,
        pack_identity=_PACK_IDENTITY,
        project_name="aptl",
        run_id=_RUN_ID,
        attempt_id=_ATTEMPT_ID,
        grants=tuple(policy.docker_authority_grants),
    )

    assert calls == ["bind"]
    assert result is None


def test_scenario_preparation_rejects_mutable_template_before_endpoint_binding() -> (
    None
):
    backend = MagicMock()
    backend.bind_local_docker_socket.return_value = LabResult(success=True)
    scenario = SimpleNamespace(
        nodes={
            "orborus": SimpleNamespace(
                runtime=_runtime(image_ref="ghcr.io/example/worker:latest")
            )
        }
    )

    policy = _authority_policy()
    with pytest.raises(
        ValueError, match="aptl.provisioner.spawn-image-identity-invalid"
    ):
        prepare_runtime_orchestration_for_scenario(
            scenario,
            backend,
            pack_identity=_PACK_IDENTITY,
            project_name="aptl",
            run_id=_RUN_ID,
            attempt_id=_ATTEMPT_ID,
            grants=tuple(policy.docker_authority_grants),
        )
    backend.bind_local_docker_socket.assert_not_called()


def test_public_plan_binds_authority_before_artifact_availability(
    tmp_path, monkeypatch
) -> None:
    from aptl.backends import raes

    calls: list[str] = []
    bundle = SimpleNamespace(
        sdl_path=tmp_path / "scenario.yaml",
        root=tmp_path,
        pack_identity=_PACK_IDENTITY,
    )
    scenario = SimpleNamespace(nodes={})
    monkeypatch.setattr(raes, "resolve_scenario_bundle", lambda *_args: bundle)
    monkeypatch.setattr(raes, "parse_sdl_file", lambda _path: scenario)
    monkeypatch.setattr(
        raes,
        "prepare_runtime_orchestration_for_scenario",
        lambda *_args, **_kwargs: calls.append("bind"),
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
            subprocess.CompletedProcess([], 1, stdout="", stderr="No such image"),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=f"{_IMAGE_ID}\n", stderr=""),
        ]
    )

    result = backend._prepare_spawn_images(_spec())

    assert result is None
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert commands[0][:2] == ["docker", "version"]
    assert commands[1][:3] == ["docker", "image", "inspect"]
    assert commands[2] == [
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        "ghcr.io/example/worker:latest",
    ]
    assert commands[3] == [
        "docker",
        "tag",
        _WORKER_REF,
        "ghcr.io/example/worker:latest",
    ]
    assert commands[4][-1] == "ghcr.io/example/worker:latest"
    assert all("pull" not in command for command in commands)
    assert all("manifest" not in command for command in commands)
    assert all("build" not in command for command in commands)
    assert all("search" not in command for command in commands)


def test_exact_worker_reference_needs_no_mutable_runtime_alias(tmp_path) -> None:
    exact_worker = f"ghcr.io/example/worker@{_DIGEST}"
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
                stdout=f'["{exact_worker}"]\t{_IMAGE_ID}\tlinux/amd64\n',
                stderr="",
            ),
        ]
    )

    result = backend._prepare_spawn_images(_spec(_runtime(image_ref=exact_worker)))

    assert result is None
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert len(commands) == 2
    assert commands[1][-1] == exact_worker
    assert all("tag" not in command for command in commands)


def test_stale_runtime_alias_fails_without_overwrite(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    stale_id = "sha256:" + "d" * 64
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
            subprocess.CompletedProcess([], 0, stdout=f"{stale_id}\n", stderr=""),
        ]
    )

    result = backend._prepare_spawn_images(_spec())

    assert result is not None
    assert result.error == (
        "Spawn image runtime alias stale for provision.node.orborus/worker."
    )
    assert all("tag" not in call.args[0] for call in backend._run.call_args_list)


@pytest.mark.parametrize(
    "alias_result",
    [
        subprocess.CompletedProcess([], 1, stdout="", stderr="permission denied"),
        subprocess.CompletedProcess(
            [], 1, stdout="", stderr="permission denied: no such image"
        ),
        subprocess.CompletedProcess([], 0, stdout="malformed\n", stderr=""),
        BackendTimeoutError("alias inspect timed out"),
    ],
)
def test_alias_inspection_error_never_authorizes_tagging(
    tmp_path, alias_result
) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )

    def _run(command, **_kwargs):
        if command[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess([], 0, stdout="linux/amd64\n", stderr="")
        if command[-1] == _WORKER_REF:
            return subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr="")
        if isinstance(alias_result, Exception):
            raise alias_result
        return alias_result

    backend._run = MagicMock(side_effect=_run)

    result = backend._prepare_spawn_images(_spec())

    assert result is not None
    assert result.error == (
        "Spawn image runtime alias inspection failed for provision.node.orborus/worker."
    )
    assert all("tag" not in call.args[0] for call in backend._run.call_args_list)


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
                stdout=f'["{_WORKER_REF}"]\t{_IMAGE_ID}\tlinux/arm64\n',
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
            subprocess.CompletedProcess([], 0, stdout=f"{_IMAGE_ID}\n", stderr=""),
        ]
    )

    assert backend._prepare_spawn_images(_spec()) is None
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert commands[1] == ["docker", "pull", _WORKER_REF]
    assert commands[2][-1] == _WORKER_REF
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
                stdout=f'["{_WORKER_REF}"]\t{_IMAGE_ID}\tlinux/arm64/v8\n',
                stderr="",
            ),
            subprocess.CompletedProcess([], 0, stdout=f"{_IMAGE_ID}\n", stderr=""),
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
    backend._docker_socket_identity = (9, 42)
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


def test_post_start_authority_uses_socket_identity_without_a_docker_cli(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend._docker_socket_identity = (9, 42)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(return_value=_holder_info())
    backend.container_exec = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 127, stdout="", stderr="not found"),
            subprocess.CompletedProcess([], 0, stdout="9:42\n", stderr=""),
        ]
    )

    assert backend._verify_runtime_orchestration(_spec()) is None
    assert backend.container_exec.call_args_list[1].args == (
        "aptl-orborus",
        ["stat", "-Lc", "%d:%i", "/var/run/docker.sock"],
    )


def test_post_start_authority_rejects_a_different_mounted_socket_identity(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend._docker_socket_identity = (9, 42)
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(return_value=_holder_info())
    backend.container_exec = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 127, stdout="", stderr="not found"),
            subprocess.CompletedProcess([], 0, stdout="9:99\n", stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec())

    assert result is not None
    assert result.error == "Docker authority runtime observation failed for orborus."


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


def _holder_info() -> dict:
    return {
        "Id": "holder-id",
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


def _child_info(
    *,
    container_id: str,
    image_id: str = _IMAGE_ID,
    parent_id: str = "holder-id",
    socket: bool = True,
    execution_id: str = _EXECUTION_ID,
    extra_mounts: list[dict] | None = None,
) -> dict:
    mounts = []
    if socket:
        mounts.append(
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        )
    mounts.extend(extra_mounts or [])
    return {
        "Id": container_id,
        "Image": image_id,
        "Mounts": mounts,
        "Config": {"Env": [f"EXECUTIONID={execution_id}"]},
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": f"container:{parent_id}",
        },
        "State": {"Running": False},
    }


def test_post_work_accepts_exact_delegated_worker_and_records_observation(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        side_effect=[_holder_info(), _child_info(container_id="worker-id")]
    )
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

    assert result is None
    assert backend._run.call_args_list[0].kwargs["timeout"] == 600
    assert backend._run.call_args_list[0].args[0] == [
        "docker",
        "ps",
        "-aq",
        "--filter",
        "ancestor=ghcr.io/example/worker:latest",
    ]
    assert backend.runtime_orchestration_observations() == (
        {
            "node_address": "provision.node.orborus",
            "authority_id": "worker-runtime",
            "template_id": "worker",
            "correlation_id": backend.runtime_orchestration_observations()[0][
                "correlation_id"
            ],
            "authority_correlation_id": _spec()
            .docker_authority_admissions[0]
            .correlation_id,
            "run_id": _RUN_ID,
            "attempt_id": _ATTEMPT_ID,
            "product_execution_id": _EXECUTION_ID,
            "container_id": "worker-id",
            "image_id": _IMAGE_ID,
            "parent_container_id": "holder-id",
            "delegated_docker_authority": True,
            "terminal": True,
        },
    )
    assert backend.runtime_orchestration_observations()[0]["correlation_id"].startswith(
        "sha256:"
    )


def test_post_work_rejects_delegated_worker_without_canonical_socket(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        side_effect=[
            _holder_info(),
            _child_info(container_id="worker-id", socket=False),
        ]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="worker-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.error == (
        "Delegated Docker authority unavailable for provision.node.orborus/worker."
    )


def test_post_work_rejects_delegated_worker_with_ungranted_host_bind(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        side_effect=[
            _holder_info(),
            _child_info(
                container_id="worker-id",
                extra_mounts=[
                    {
                        "Type": "bind",
                        "Source": "/var/run",
                        "Destination": "/host-run",
                        "RW": True,
                    }
                ],
            ),
        ]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="worker-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.error == (
        "Delegated Docker authority unavailable for provision.node.orborus/worker."
    )


def test_post_start_rejects_descendant_image_selected_by_ancestor_filter(
    tmp_path,
) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    child = _child_info(
        container_id="descendant-child-id",
        image_id="sha256:" + "c" * 64,
    )
    backend.container_inspect = MagicMock(side_effect=[_holder_info(), child])
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
    child_running = _child_info(container_id="spawned-child-id")
    child_running["State"] = {
        "Running": True,
        "StartedAt": "2020-01-01T00:00:00Z",
    }
    child_stopped = {"State": {"Running": False}}
    backend.container_inspect = MagicMock(
        side_effect=[_holder_info(), child_running, child_stopped, child_stopped]
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


def test_startup_attestation_does_not_enumerate_children_before_semantic_work(
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
    backend._run.assert_not_called()


def test_post_work_attestation_requires_an_observed_child(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        return_value={
            **_holder_info(),
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
        "Spawned-child correlation unavailable for provision.node.orborus/worker."
    )


def test_foreign_parent_correlation_fails_without_destructive_action(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        side_effect=[
            _holder_info(),
            _child_info(container_id="foreign-id", parent_id="foreign-holder"),
        ]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="foreign-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.error == (
        "Spawned-child correlation unavailable for provision.node.orborus/worker."
    )
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert all(command[1] not in {"stop", "kill"} for command in commands)


def test_foreign_product_execution_is_not_owned_or_mutated(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    backend.container_inspect = MagicMock(
        side_effect=[
            _holder_info(),
            _child_info(
                container_id="foreign-id",
                execution_id="another-shuffle-execution",
            ),
        ]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="foreign-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(_spec(), require_children=True)

    assert result is not None
    assert result.error == (
        "Spawned-child correlation unavailable for provision.node.orborus/worker."
    )
    commands = [call.args[0] for call in backend._run.call_args_list]
    assert all(command[1] not in {"stop", "kill"} for command in commands)


def test_nondelegated_app_is_owned_by_worker_and_remains_socket_free(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    worker = _child_info(container_id="worker-id")
    app = _child_info(
        container_id="app-id",
        image_id="sha256:" + "e" * 64,
        parent_id="worker-id",
        socket=False,
    )
    backend.container_inspect = MagicMock(side_effect=[_holder_info(), worker, app])
    app_inspect = f'["{_APP_REF}"]\t{"sha256:" + "e" * 64}\tlinux/amd64\n'
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="worker-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
            subprocess.CompletedProcess([], 0, stdout="app-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=app_inspect, stderr=""),
        ]
    )

    result = backend._verify_runtime_orchestration(
        _spec(_runtime(include_app=True)), require_children=True
    )

    assert result is None
    observations = backend.runtime_orchestration_observations()
    assert [item["template_id"] for item in observations] == [
        "worker",
        "http-1-4-0",
    ]
    assert observations[1]["parent_container_id"] == "worker-id"
    assert observations[1]["delegated_docker_authority"] is False


def test_nondelegated_app_rejects_socket_propagation(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    app_id = "sha256:" + "e" * 64
    backend.container_inspect = MagicMock(
        side_effect=[
            _holder_info(),
            _child_info(container_id="worker-id"),
            _child_info(
                container_id="app-id",
                image_id=app_id,
                parent_id="worker-id",
                socket=True,
            ),
        ]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="worker-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
            subprocess.CompletedProcess([], 0, stdout="app-id\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=f'["{_APP_REF}"]\t{app_id}\tlinux/amd64\n',
                stderr="",
            ),
        ]
    )

    result = backend._verify_runtime_orchestration(
        _spec(_runtime(include_app=True)), require_children=True
    )

    assert result is not None
    assert result.error == (
        "Docker authority propagated to spawned child "
        "provision.node.orborus/http-1-4-0."
    )


def test_nondelegated_app_rejects_ungranted_host_bind(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    backend.revalidate_local_docker_socket = MagicMock(
        return_value=LabResult(success=True)
    )
    app_id = "sha256:" + "e" * 64
    backend.container_inspect = MagicMock(
        side_effect=[
            _holder_info(),
            _child_info(container_id="worker-id"),
            _child_info(
                container_id="app-id",
                image_id=app_id,
                parent_id="worker-id",
                socket=False,
                extra_mounts=[
                    {
                        "Type": "bind",
                        "Source": "/etc",
                        "Destination": "/host-etc",
                        "RW": False,
                    }
                ],
            ),
        ]
    )
    backend.container_exec = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, stdout="daemon-a\n", stderr="")
    )
    backend._run = MagicMock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="worker-id\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=_CHILD_INSPECT, stderr=""),
            subprocess.CompletedProcess([], 0, stdout="app-id\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=f'["{_APP_REF}"]\t{app_id}\tlinux/amd64\n',
                stderr="",
            ),
        ]
    )

    result = backend._verify_runtime_orchestration(
        _spec(_runtime(include_app=True)), require_children=True
    )

    assert result is not None
    assert result.error == (
        "Docker authority propagated to spawned child "
        "provision.node.orborus/http-1-4-0."
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
