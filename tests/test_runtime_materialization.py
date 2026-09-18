"""Runtime-authority materialization and containment regression tests (#956)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError
from raes.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment._compose_node_generation import _operational_config
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.ssh_compose import SSHComposeBackend
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.deployment.runtime_materialization import (
    SHARED_DOCKER_PROFILE,
    RuntimeContainmentEvidence,
    RuntimeMaterializationProfile,
    effective_runtime_contract_issues,
    qualify_runtime_materialization,
)
from aptl.core.runtime_authority_policy import (
    RuntimeAuthorityPolicy,
    load_runtime_authority_policy,
)
from aptl.core.scenario_bundle import PackIdentity
from aptl.runtime_authority import DeploymentDockerAuthorityAdmission
from aptl.utils.pathsafe import PathContainmentError


_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_QUALIFIED_PROFILE = RuntimeMaterializationProfile(
    name="test-qualified-docker",
    containment_evidence=RuntimeContainmentEvidence(
        profile_id="test-only-profile",
        target_identity="test-only-target",
        boundary_attestation_ref="test-only-attestation",
        negative_probe_ref="test-only-negative-probe",
    ),
)


def _node(runtime: RuntimeConfiguration, *, image_backed: bool = True):
    node = DeploymentNodeRealization(
        address="provision.node.workload",
        name="workload",
        service_name="workload",
        container_name="aptl-workload",
        networks=("shared",),
        runtime=runtime,
    )
    images = (
        DeploymentImageRealization(
            address=node.address,
            service_name="workload",
            source_name="workload",
            source_version="workload@" + _DIGEST_A,
            image_ref="example/workload@" + _DIGEST_A,
            mode="pull",
            policy_rule="digest-pinned",
        ),
    ) if image_backed else ()
    return node, images


def _spec(
    runtime: RuntimeConfiguration,
    *,
    image_backed: bool = True,
    authority: bool = False,
    pack_digest: str = _DIGEST_A,
) -> DeploymentRealizationSpec:
    node, images = _node(runtime, image_backed=image_backed)
    admissions = ()
    if authority:
        admissions = (
            DeploymentDockerAuthorityAdmission(
                node_address=node.address,
                service_name="workload",
                engine="docker",
                privilege_class="host_root_equivalent",
                endpoint_kind="unix_socket",
                endpoint_source="/var/run/docker.sock",
                endpoint_target="/var/run/docker.sock",
                endpoint_read_write=True,
                spawn_requirements=(),
                authority_id="authority",
                image_template_ids=("worker", "app"),
            ),
        )
    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(node,),
        networks=(),
        images=images,
        docker_authority_admissions=admissions,
        pack_identity=PackIdentity("fixture", "1.0.0", pack_digest),
    )


def _policy_payload(*, pack_digest: str = _DIGEST_A) -> dict[str, object]:
    return {
        "schema_version": "aptl.runtime-authority-policy/v1",
        "target": {
            "profile_id": "fixture-isolated-daemon",
            "provider": "ssh-compose",
            "ssh_host": "range.example.test",
            "daemon_id": "daemon-fixture",
            "endpoint_source": "/var/run/docker.sock",
        },
        "grants": [
            {
                "pack_id": "fixture",
                "pack_version": "1.0.0",
                "pack_set_digest": pack_digest,
                "component_address": "provision.node.workload",
                "authority_id": "authority",
                "endpoint_source": "/var/run/docker.sock",
                "image_template_ids": ["worker", "app"],
                "delegated_template_ids": ["worker"],
            }
        ],
    }


def test_runtime_authority_policy_is_strict_and_delegation_only_narrows() -> None:
    payload = _policy_payload()
    payload["grants"][0]["delegated_template_ids"] = ["unknown"]

    with pytest.raises(ValidationError, match="delegated"):
        RuntimeAuthorityPolicy.model_validate(payload)

    payload = _policy_payload()
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="unexpected"):
        RuntimeAuthorityPolicy.model_validate(payload)

    payload = _policy_payload()
    payload["target"]["ssh_host"] = "localhost"
    with pytest.raises(ValidationError, match="remote non-loopback"):
        RuntimeAuthorityPolicy.model_validate(payload)


def test_runtime_authority_policy_loads_nofollow_and_absence_means_zero_grants(
    tmp_path: Path,
) -> None:
    assert load_runtime_authority_policy(tmp_path, None).grants == ()

    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy_payload()), encoding="utf-8")
    policy = load_runtime_authority_policy(tmp_path, "policy.json")
    assert policy.target.daemon_id == "daemon-fixture"

    link = tmp_path / "policy-link.json"
    link.symlink_to(policy_path)
    with pytest.raises(PathContainmentError):
        load_runtime_authority_policy(tmp_path, "policy-link.json")


def test_backend_runtime_authority_policy_cannot_be_replaced(tmp_path: Path) -> None:
    backend = DockerComposeBackend(tmp_path)
    policy = RuntimeAuthorityPolicy.empty()

    backend.configure_runtime_authority_policy(policy)

    with pytest.raises(ValueError, match="already configured"):
        backend.configure_runtime_authority_policy(policy)


def test_compose_lowering_preserves_supported_runtime_security_fields() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {
            "linux_capabilities": {
                "add": ["CAP_NET_ADMIN"],
                "drop": ["CAP_CHOWN"],
            },
            "container": {
                "privileged": True,
                "read_only_rootfs": True,
                "shm_size": "64 MiB",
                "namespaces": {
                    "pid": "host",
                    "ipc": "private",
                    "userns": "host",
                    "uts": "host",
                    "cgroup": "private",
                },
                "devices": [
                    {
                        "host_path": "/dev/net/tun",
                        "container_path": "/dev/net/tun",
                        "permissions": "rwm",
                    }
                ],
                "device_cgroup_rules": ["c 10:200 rwm"],
                "seccomp_profile": "unconfined",
                "security_opt": ["no-new-privileges=false"],
                "cgroup_parent": "scenario.slice",
                "runtime_name": "runc",
                "group_add": ["1000"],
                "extra_hosts": [{"hostname": "db", "address": "10.0.0.5"}],
                "dns": ["10.0.0.2"],
                "dns_options": ["use-vc"],
                "dns_search": ["scenario.test"],
                "log_driver": "json-file",
                "log_options": {"max-size": "10m"},
            },
        }
    )

    config = _operational_config(runtime)

    assert config["cap_add"] == ["NET_ADMIN"]
    assert config["cap_drop"] == ["CHOWN"]
    assert config["privileged"] is True
    assert config["read_only"] is True
    assert config["pid"] == "host"
    assert config["ipc"] == "private"
    assert config["userns_mode"] == "host"
    assert config["uts"] == "host"
    assert config["cgroup"] == "private"
    assert config["devices"] == ["/dev/net/tun:/dev/net/tun:rwm"]
    assert config["device_cgroup_rules"] == ["c 10:200 rwm"]
    assert config["security_opt"] == [
        "no-new-privileges=false",
        "seccomp=unconfined",
    ]
    assert config["cgroup_parent"] == "scenario.slice"
    assert config["runtime"] == "runc"
    assert config["group_add"] == ["1000"]
    assert config["extra_hosts"] == ["db:10.0.0.5"]
    assert config["dns_opt"] == ["use-vc"]
    assert config["dns_search"] == ["scenario.test"]
    assert config["logging"] == {
        "driver": "json-file",
        "options": {"max-size": "10m"},
    }


def test_shared_daemon_rejects_high_authority_with_precise_limitation() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {"container": {"privileged": True}}
    )

    issues = qualify_runtime_materialization(
        _spec(runtime),
        profile=SHARED_DOCKER_PROFILE,
        policy=RuntimeAuthorityPolicy.empty(),
    )

    assert len(issues) == 1
    assert issues[0].node_address == "provision.node.workload"
    assert issues[0].field == "runtime.container.privileged"
    assert issues[0].backend_profile == "shared-docker"
    assert "isolated" in issues[0].limitation


def test_shared_daemon_rejects_authored_host_bind_as_escape_surface() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {
            "mounts": [
                {
                    "source_kind": "bind",
                    "source": "/etc",
                    "target": "/host-etc",
                    "read_only": True,
                }
            ]
        }
    )

    issues = qualify_runtime_materialization(
        _spec(runtime),
        profile=SHARED_DOCKER_PROFILE,
        policy=RuntimeAuthorityPolicy.empty(),
    )

    assert len(issues) == 1
    assert issues[0].field == "runtime.mounts[0]"
    assert "isolated" in issues[0].limitation


def test_effective_model_rejects_undeclared_host_bind_without_runtime_fields() -> None:
    runtime = RuntimeConfiguration.model_validate({})
    payload = {
        "services": {
            "workload": {
                "image": "example/workload",
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/",
                        "target": "/host",
                        "read_only": False,
                    }
                ],
            }
        }
    }

    issues = effective_runtime_contract_issues(
        payload,
        _spec(runtime),
        profile=SHARED_DOCKER_PROFILE,
    )

    assert len(issues) == 1
    assert issues[0].field == "runtime.mounts"
    assert "undeclared runtime authority" in issues[0].limitation


def test_compose_lowering_preserves_authored_mount_contract() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {
            "mounts": [
                {
                    "source_kind": "bind",
                    "source": "/scenario/input",
                    "target": "/input",
                    "read_only": True,
                    "propagation": "rprivate",
                },
                {
                    "source_kind": "volume",
                    "source": "scenario-data",
                    "target": "/data",
                },
                {"source_kind": "tmpfs", "target": "/scratch"},
            ]
        }
    )

    assert _operational_config(runtime)["volumes"] == [
        {
            "type": "bind",
            "source": "/scenario/input",
            "target": "/input",
            "read_only": True,
            "bind": {"propagation": "rprivate"},
        },
        {
            "type": "volume",
            "source": "scenario-data",
            "target": "/data",
            "read_only": False,
        },
        {"type": "tmpfs", "target": "/scratch", "read_only": False},
    ]


def test_generic_substrate_rejects_non_volume_mount_before_materialization() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {"mounts": [{"source_kind": "tmpfs", "target": "/scratch"}]}
    )

    issues = qualify_runtime_materialization(
        _spec(runtime, image_backed=False),
        profile=_QUALIFIED_PROFILE,
        policy=RuntimeAuthorityPolicy.model_validate(_policy_payload()),
    )

    assert len(issues) == 1
    assert issues[0].field == "runtime.mounts[0]"
    assert "generic substrate" in issues[0].limitation


def test_generic_substrate_rejects_unimplemented_field_before_materialization() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {"container": {"privileged": True}}
    )

    issues = qualify_runtime_materialization(
        _spec(runtime, image_backed=False),
        profile=_QUALIFIED_PROFILE,
        policy=RuntimeAuthorityPolicy.model_validate(_policy_payload()),
    )

    assert len(issues) == 1
    assert issues[0].field == "runtime.container.privileged"
    assert "generic substrate" in issues[0].limitation


def test_isolated_profile_accepts_faithful_image_backed_authority() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {
            "container": {
                "privileged": True,
                "security_opt": ["seccomp=unconfined"],
                "namespaces": {"pid": "host"},
            },
            "linux_capabilities": {
                "add": ["CAP_SYS_ADMIN"],
                "drop": ["CAP_CHOWN"],
            },
        }
    )
    policy = RuntimeAuthorityPolicy.model_validate(_policy_payload())

    assert qualify_runtime_materialization(
        _spec(runtime), profile=_QUALIFIED_PROFILE, policy=policy
    ) == ()


def test_operator_grant_does_not_rewrite_or_filter_authored_runtime() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {
            "container": {
                "privileged": True,
                "security_opt": ["seccomp=unconfined"],
                "read_only_rootfs": True,
            },
            "linux_capabilities": {
                "add": ["CAP_SYS_ADMIN"],
                "drop": ["CAP_CHOWN"],
            },
        }
    )
    spec = _spec(runtime, authority=True)
    before = runtime.model_dump(mode="json", by_alias=True)

    issues = qualify_runtime_materialization(
        spec,
        profile=_QUALIFIED_PROFILE,
        policy=RuntimeAuthorityPolicy.model_validate(_policy_payload()),
    )

    assert issues == ()
    assert spec.nodes[0].runtime.model_dump(mode="json", by_alias=True) == before
    config = _operational_config(spec.nodes[0].runtime)
    assert config["privileged"] is True
    assert config["security_opt"] == ["seccomp=unconfined"]
    assert config["read_only"] is True
    assert config["cap_add"] == ["SYS_ADMIN"]
    assert config["cap_drop"] == ["CHOWN"]


def test_raw_socket_requires_exact_grant_and_pack_digest() -> None:
    runtime = RuntimeConfiguration.model_validate({})
    policy = RuntimeAuthorityPolicy.model_validate(_policy_payload())

    issues = qualify_runtime_materialization(
        _spec(runtime, authority=True, pack_digest=_DIGEST_B),
        profile=_QUALIFIED_PROFILE,
        policy=policy,
    )

    assert len(issues) == 1
    assert issues[0].field == "runtime.orchestration_authorities"
    assert "grant" in issues[0].limitation


def test_unsupported_compose_field_is_never_silently_dropped() -> None:
    runtime = RuntimeConfiguration.model_validate(
        {"container": {"masked_paths": ["/proc/kcore"]}}
    )

    issues = qualify_runtime_materialization(
        _spec(runtime),
        profile=_QUALIFIED_PROFILE,
        policy=RuntimeAuthorityPolicy.model_validate(_policy_payload()),
    )

    assert len(issues) == 1
    assert issues[0].field == "runtime.container.masked_paths"
    assert "Compose" in issues[0].limitation


@pytest.mark.parametrize("field", ["required", "effective", "process_overrides"])
def test_unimplemented_capability_dimensions_are_never_silently_dropped(
    field: str,
) -> None:
    value: object = ["CAP_NET_ADMIN"]
    if field == "process_overrides":
        value = [
            {
                "subject": {"name": "worker"},
                "add": ["CAP_NET_ADMIN"],
            }
        ]
    runtime = RuntimeConfiguration.model_validate(
        {"linux_capabilities": {field: value}}
    )

    issues = qualify_runtime_materialization(
        _spec(runtime),
        profile=_QUALIFIED_PROFILE,
        policy=RuntimeAuthorityPolicy.model_validate(_policy_payload()),
    )

    assert len(issues) == 1
    assert issues[0].field == f"runtime.linux_capabilities.{field}"
    assert "faithful lowering" in issues[0].limitation


def test_runtime_qualification_precedes_ownership_and_mixed_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = RuntimeConfiguration.model_validate(
        {"container": {"masked_paths": ["/proc/kcore"]}}
    )
    backend = DockerComposeBackend(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        backend,
        "_ensure_resource_ownership",
        lambda *args, **kwargs: calls.append("ownership"),
    )
    monkeypatch.setattr(
        backend,
        "_materialize_image_free_nodes",
        lambda *args, **kwargs: calls.append("materialize"),
    )

    result = backend.realize(_spec(runtime), scenario_root=tmp_path)

    assert result.success is False
    assert calls == []
    assert "node=provision.node.workload" in result.error
    assert "field=runtime.container.masked_paths" in result.error
    assert "backend=shared-docker" in result.error


def test_static_effective_model_is_compared_before_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  workload:\n    image: example/workload\n",
        encoding="utf-8",
    )
    runtime = RuntimeConfiguration.model_validate(
        {"container": {"read_only_rootfs": True}}
    )
    backend = DockerComposeBackend(tmp_path)
    ownership_calls: list[str] = []
    monkeypatch.setattr(
        backend,
        "_ensure_resource_ownership",
        lambda *args, **kwargs: ownership_calls.append("ownership"),
    )
    monkeypatch.setattr(
        backend,
        "_run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            0,
            json.dumps({"services": {"workload": {"image": "example/workload"}}}),
            "",
        ),
    )

    result = backend.realize(_spec(runtime), scenario_root=tmp_path)

    assert result.success is False
    assert ownership_calls == []
    assert "field=runtime.container.read_only_rootfs" in result.error
    assert "effective Compose model" in result.error


def test_static_undeclared_host_bind_is_rejected_before_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  workload:\n    image: example/workload\n",
        encoding="utf-8",
    )
    backend = DockerComposeBackend(tmp_path)
    ownership_calls: list[str] = []
    monkeypatch.setattr(
        backend,
        "_ensure_resource_ownership",
        lambda *args, **kwargs: ownership_calls.append("ownership"),
    )
    monkeypatch.setattr(
        backend,
        "_run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                {
                    "services": {
                        "workload": {
                            "image": "example/workload",
                            "volumes": [
                                {
                                    "type": "bind",
                                    "source": "/",
                                    "target": "/host",
                                }
                            ],
                        }
                    }
                }
            ),
            "",
        ),
    )

    result = backend.realize(
        _spec(RuntimeConfiguration.model_validate({})),
        scenario_root=tmp_path,
    )

    assert result.success is False
    assert ownership_calls == []
    assert "field=runtime.mounts" in result.error
    assert "undeclared runtime authority" in result.error


def _isolated_backend(tmp_path: Path) -> SSHComposeBackend:
    backend = SSHComposeBackend(
        tmp_path,
        host="range.example.test",
        user="aptl",
    )
    backend.configure_runtime_authority_policy(
        RuntimeAuthorityPolicy.model_validate(_policy_payload())
    )
    return backend


def _exclusive_daemon_run(argv: list[str], **_kwargs: object):
    if argv[:3] == ["docker", "info", "--format"]:
        output = "daemon-fixture\n"
    elif argv[:3] == ["docker", "ps", "-aq"]:
        output = ""
    elif argv[:4] == ["docker", "volume", "ls", "-q"]:
        output = ""
    elif argv[:4] == ["docker", "network", "ls", "--format"]:
        output = "bridge\nhost\nnone\n"
    else:  # pragma: no cover - makes new qualification probes explicit
        raise AssertionError(argv)
    return subprocess.CompletedProcess(argv, 0, output, "")


def test_empty_ssh_daemon_does_not_claim_contained_high_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = RuntimeConfiguration.model_validate(
        {
            "container": {
                "privileged": True,
                "security_opt": ["seccomp=unconfined"],
                "namespaces": {"pid": "host"},
            }
        }
    )
    backend = _isolated_backend(tmp_path)
    monkeypatch.setattr(backend, "_run", _exclusive_daemon_run)

    failure = backend._runtime_materialization_preflight(
        _spec(runtime, authority=True)
    )

    assert failure is not None
    assert "backend=shared-docker" in failure.error
    assert "isolated scenario-exclusive daemon" in failure.error
    assert backend._runtime_containment_evidence == {
        "daemon_id": "daemon-fixture",
        "provider": "ssh-compose",
        "containment_profile": "shared-docker",
        "foreign_containers": 0,
        "foreign_volumes": 0,
        "foreign_networks": 0,
    }


def test_isolated_target_rejects_foreign_daemon_resources_as_escape_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _isolated_backend(tmp_path)

    def run_with_foreign_volume(argv: list[str], **kwargs: object):
        result = _exclusive_daemon_run(argv, **kwargs)
        if argv[:4] == ["docker", "volume", "ls", "-q"]:
            return subprocess.CompletedProcess(argv, 0, "operator-secrets\n", "")
        return result

    monkeypatch.setattr(backend, "_run", run_with_foreign_volume)

    failure = backend._runtime_materialization_preflight(
        _spec(RuntimeConfiguration.model_validate({}), authority=True)
    )

    assert failure is not None
    assert failure.success is False
    assert failure.error == (
        "Isolated Docker target contains foreign volumes; refusing runtime authority."
    )
    assert backend._runtime_containment_evidence == {}


def test_isolated_target_revalidates_exact_daemon_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _isolated_backend(tmp_path)
    daemon_ids = iter(["daemon-fixture\n", "replacement-daemon\n"])

    def changing_daemon(argv: list[str], **kwargs: object):
        if argv[:3] == ["docker", "info", "--format"]:
            return subprocess.CompletedProcess(argv, 0, next(daemon_ids), "")
        return _exclusive_daemon_run(argv, **kwargs)

    monkeypatch.setattr(backend, "_run", changing_daemon)

    assert backend.bind_local_docker_socket().success is True
    result = backend.revalidate_local_docker_socket()

    assert result.success is False
    assert result.error == "Docker control endpoint identity changed."
