"""Read-only qualification of the complete authored runtime contract.

Qualification is deliberately pure: it classifies what the selected backend
can faithfully lower and contain, but creates no ownership receipts, files,
images, networks, volumes, or containers.  Valid SDL that falls outside the
profile is an unsupported materialization, never invalid or unsafe content.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.runtime_authority_policy import RuntimeAuthorityPolicy


@dataclass(frozen=True)
class RuntimeContainmentEvidence:
    """Independent boundary evidence carried by a qualified backend profile."""

    profile_id: str
    target_identity: str
    boundary_attestation_ref: str
    negative_probe_ref: str


@dataclass(frozen=True)
class RuntimeMaterializationProfile:
    """The selected backend's proven runtime-authority capability envelope."""

    name: str
    containment_evidence: RuntimeContainmentEvidence | None = None


SHARED_DOCKER_PROFILE = RuntimeMaterializationProfile(
    name="shared-docker",
)


@dataclass(frozen=True)
class RuntimeMaterializationIssue:
    """One precise unsupported-materialization diagnostic."""

    node_address: str
    field: str
    backend_profile: str
    limitation: str

    def render(self) -> str:
        """Return a bounded stable backend diagnostic."""

        return (
            "aptl.provisioner.runtime-materialization-unsupported: "
            f"node={self.node_address} field={self.field} "
            f"backend={self.backend_profile} limitation={self.limitation}"
        )


_COMPOSE_FIELDS = frozenset(
    {
        "entrypoint",
        "command",
        "log_driver",
        "log_options",
        "namespaces",
        "privileged",
        "read_only_rootfs",
        "autoremove",
        "shm_size",
        "cgroup_parent",
        "runtime_name",
        "devices",
        "device_cgroup_rules",
        "seccomp_profile",
        "security_opt",
        "extra_hosts",
        "dns",
        "dns_options",
        "dns_search",
        "group_add",
        "init_process",
    }
)
_COMPOSE_UNSUPPORTED_FIELDS = frozenset(
    {"masked_paths", "read_only_paths", "publish_all_ports"}
)
_HIGH_AUTHORITY_CONTAINER_FIELDS = frozenset(
    {
        "privileged",
        "namespaces",
        "devices",
        "device_cgroup_rules",
        "seccomp_profile",
        "security_opt",
        "cgroup_parent",
        "runtime_name",
    }
)


def _present(value: object) -> bool:
    """Whether a runtime value selects material state rather than omission."""

    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, bool):
        return value
    if hasattr(value, "model_dump"):
        return bool(value.model_dump(exclude_defaults=True))
    try:
        return bool(value)
    except TypeError:
        return True


def _container_fields(runtime: object) -> dict[str, object]:
    container = getattr(runtime, "container", None)
    if container is None:
        return {}
    return {
        name: getattr(container, name, None)
        for name in container.__class__.model_fields
        if name != "description" and _present(getattr(container, name, None))
    }


def _issue(
    node_address: str,
    field: str,
    profile: RuntimeMaterializationProfile,
    limitation: str,
) -> RuntimeMaterializationIssue:
    return RuntimeMaterializationIssue(
        node_address=node_address,
        field=field,
        backend_profile=profile.name,
        limitation=limitation,
    )


def _container_issues(
    node: object,
    *,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> list[RuntimeMaterializationIssue]:
    runtime = getattr(node, "runtime", None)
    if runtime is None:
        return []
    address = str(getattr(node, "address", ""))
    fields = _container_fields(runtime)
    capabilities = getattr(runtime, "linux_capabilities", None)
    capability_selected = bool(
        capabilities is not None
        and (
            getattr(capabilities, "add", ())
            or getattr(capabilities, "drop", ())
            or getattr(capabilities, "required", ())
            or getattr(capabilities, "effective", ())
            or getattr(capabilities, "process_overrides", ())
        )
    )

    if not image_backed and (fields or capability_selected):
        selected = next(iter(fields), "linux_capabilities")
        return [
            _issue(
                address,
                f"runtime.container.{selected}"
                if selected != "linux_capabilities"
                else "runtime.linux_capabilities",
                profile,
                "generic substrate does not faithfully lower this field",
            )
        ]

    if capabilities is not None:
        unsupported_capability = next(
            (
                name
                for name in ("required", "effective", "process_overrides")
                if _present(getattr(capabilities, name, None))
            ),
            None,
        )
        if unsupported_capability is not None:
            return [
                _issue(
                    address,
                    f"runtime.linux_capabilities.{unsupported_capability}",
                    profile,
                    "selected backend has no faithful lowering for this capability dimension",
                )
            ]

    namespaces = getattr(getattr(runtime, "container", None), "namespaces", None)
    if namespaces is not None and getattr(namespaces, "network", None) is not None:
        return [
            _issue(
                address,
                "runtime.container.namespaces.network",
                profile,
                "selected backend cannot independently read back the joined network namespace owner",
            )
        ]
    init_process = getattr(getattr(runtime, "container", None), "init_process", None)
    if init_process is not None and any(
        _present(getattr(init_process, name, None))
        for name in ("implementation", "executable_path", "reaps_children", "argv")
    ):
        return [
            _issue(
                address,
                "runtime.container.init_process",
                profile,
                "selected backend supports the standard init toggle but not a custom init contract",
            )
        ]

    unsupported = next(
        (name for name in fields if name in _COMPOSE_UNSUPPORTED_FIELDS), None
    )
    if unsupported is not None:
        return [
            _issue(
                address,
                f"runtime.container.{unsupported}",
                profile,
                "Docker Compose has no faithful lowering for this field",
            )
        ]
    unknown = next((name for name in fields if name not in _COMPOSE_FIELDS), None)
    if unknown is not None:
        return [
            _issue(
                address,
                f"runtime.container.{unknown}",
                profile,
                "selected backend has no faithful lowering for this field",
            )
        ]

    high_field = next(
        (name for name in fields if name in _HIGH_AUTHORITY_CONTAINER_FIELDS), None
    )
    if (
        high_field is None
        and capabilities is not None
        and getattr(capabilities, "add", ())
    ):
        high_field = "linux_capabilities"
    if high_field is not None and profile.containment_evidence is None:
        field = (
            "runtime.linux_capabilities"
            if high_field == "linux_capabilities"
            else f"runtime.container.{high_field}"
        )
        return [
            _issue(
                address,
                field,
                profile,
                "requires an independently qualified isolated execution target",
            )
        ]
    return []


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value) or "")


def _mount_issues(
    node: object,
    *,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> list[RuntimeMaterializationIssue]:
    """Qualify authored filesystem access as part of the runtime boundary."""

    runtime = getattr(node, "runtime", None)
    mounts = getattr(runtime, "mounts", ()) if runtime is not None else ()
    address = str(getattr(node, "address", ""))
    for index, mount in enumerate(mounts):
        field = f"runtime.mounts[{index}]"
        kind = _enum_value(getattr(mount, "source_kind", ""))
        source = str(getattr(mount, "source", "") or "")
        fields_set = getattr(mount, "model_fields_set", set())
        if not image_backed and kind != "volume":
            return [
                _issue(
                    address,
                    field,
                    profile,
                    "generic substrate faithfully lowers named volumes only",
                )
            ]
        if kind not in {"bind", "volume", "tmpfs"}:
            return [
                _issue(
                    address,
                    field,
                    profile,
                    f"selected backend has no faithful {kind or 'unspecified'} mount lowering",
                )
            ]
        if kind in {"bind", "volume"} and not source:
            return [
                _issue(
                    address,
                    field,
                    profile,
                    f"{kind} source requires an operator-resolvable concrete value",
                )
            ]
        if getattr(mount, "filesystem_type", "") or getattr(mount, "options", ()):
            return [
                _issue(
                    address,
                    field,
                    profile,
                    "selected backend cannot faithfully lower mount filesystem options",
                )
            ]
        propagation = _enum_value(getattr(mount, "propagation", ""))
        if (
            "propagation" in fields_set
            and propagation
            not in {"private", "rprivate", "shared", "rshared", "slave", "rslave"}
        ) or (kind != "bind" and "propagation" in fields_set):
            return [
                _issue(
                    address,
                    field,
                    profile,
                    "mount propagation is not faithfully expressible for this mount",
                )
            ]
        if kind == "bind":
            if PurePosixPath(source) == PurePosixPath("/var/run/docker.sock"):
                return [
                    _issue(
                        address,
                        field,
                        profile,
                        "Docker control access requires an exact orchestration-authority grant",
                    )
                ]
            if profile.containment_evidence is None:
                return [
                    _issue(
                        address,
                        field,
                        profile,
                        "host bind access requires an independently qualified isolated execution target",
                    )
                ]
    return []


def _authority_issues(
    realization: DeploymentRealizationSpec,
    *,
    profile: RuntimeMaterializationProfile,
    policy: RuntimeAuthorityPolicy,
) -> list[RuntimeMaterializationIssue]:
    issues: list[RuntimeMaterializationIssue] = []
    for admission in realization.docker_authority_admissions:
        if profile.containment_evidence is None:
            issues.append(
                _issue(
                    admission.node_address,
                    "runtime.orchestration_authorities",
                    profile,
                    "raw daemon authority requires an isolated scenario-exclusive daemon",
                )
            )
            continue
        grant = policy.grant_for(
            realization.pack_identity,
            component_address=admission.node_address,
            authority_id=admission.authority_id,
            endpoint_source=admission.endpoint_source,
            image_template_ids=admission.image_template_ids,
        )
        if grant is None:
            issues.append(
                _issue(
                    admission.node_address,
                    "runtime.orchestration_authorities",
                    profile,
                    "no exact immutable-pack operator grant authorizes the selected endpoint",
                )
            )
    return issues


def qualify_runtime_materialization(
    realization: DeploymentRealizationSpec,
    *,
    profile: RuntimeMaterializationProfile,
    policy: RuntimeAuthorityPolicy,
) -> tuple[RuntimeMaterializationIssue, ...]:
    """Qualify the complete graph without mutating deployment state."""

    imaged = {image.address for image in realization.images}
    issues = [
        issue
        for node in realization.nodes
        for issue in _container_issues(
            node,
            image_backed=node.address in imaged,
            profile=profile,
        )
    ]
    issues.extend(
        issue
        for node in realization.nodes
        for issue in _mount_issues(
            node,
            image_backed=node.address in imaged,
            profile=profile,
        )
    )
    issues.extend(_authority_issues(realization, profile=profile, policy=policy))
    return tuple(issues)


_RUNTIME_COMPOSE_FIELDS = {
    "volumes": "runtime.mounts",
    "restart": "runtime.operational_policy.restart",
    "mem_limit": "runtime.operational_policy.resource_limits.memory",
    "command": "runtime.container.command",
    "entrypoint": "runtime.container.entrypoint",
    "dns": "runtime.container.dns",
    "group_add": "runtime.container.group_add",
    "shm_size": "runtime.container.shm_size",
    "privileged": "runtime.container.privileged",
    "read_only": "runtime.container.read_only_rootfs",
    "pid": "runtime.container.namespaces.pid",
    "ipc": "runtime.container.namespaces.ipc",
    "userns_mode": "runtime.container.namespaces.userns",
    "uts": "runtime.container.namespaces.uts",
    "cgroup": "runtime.container.namespaces.cgroup",
    "devices": "runtime.container.devices",
    "device_cgroup_rules": "runtime.container.device_cgroup_rules",
    "security_opt": "runtime.container.security_opt",
    "cgroup_parent": "runtime.container.cgroup_parent",
    "runtime": "runtime.container.runtime_name",
    "extra_hosts": "runtime.container.extra_hosts",
    "dns_opt": "runtime.container.dns_options",
    "dns_search": "runtime.container.dns_search",
    "logging": "runtime.container.log_driver",
    "init": "runtime.container.init_process",
    "cap_add": "runtime.linux_capabilities.add",
    "cap_drop": "runtime.linux_capabilities.drop",
}

# Complete Compose service authority surface supported by this backend.  Fields
# outside this set may affect application behaviour, but cannot cross the
# container/daemon boundary.  Every field in this set is either matched to the
# admitted runtime contract below or rejected as undeclared authority.  This is
# deliberately an allow/expected contract, not a list of whichever dangerous
# values a caller happened to request.
_COMPOSE_AUTHORITY_FIELDS = frozenset(
    {
        "privileged",
        "security_opt",
        "cap_add",
        "cap_drop",
        "devices",
        "device_cgroup_rules",
        "pid",
        "ipc",
        "network_mode",
        "userns_mode",
        "uts",
        "cgroup",
        "cgroup_parent",
        "runtime",
        "volumes",
        "tmpfs",
        "volumes_from",
        "use_api_socket",
        "group_add",
        "user",
        "sysctls",
        "credential_spec",
        "isolation",
        "gpus",
    }
)


def _compose_authority_field(field: str) -> str:
    """Return the portable path when one exists, otherwise the Compose path."""

    return _RUNTIME_COMPOSE_FIELDS.get(field, f"compose.services[].{field}")


def _undeclared_mount_authority(
    actual: object,
    expected: object,
    *,
    allow_docker_socket: bool,
) -> bool:
    """Whether an effective service adds a bind/tmpfs/socket mount.

    Named Docker volumes remain inside the selected daemon and are separately
    checked by the stateful/content realization gates.  Bind and tmpfs mounts
    cross or expand the service boundary and therefore require an exact runtime
    declaration (the orchestration gate separately owns its admitted socket).
    """

    if not isinstance(actual, Sequence) or isinstance(actual, (str, bytes)):
        return bool(actual)
    expected_items = (
        expected
        if isinstance(expected, Sequence) and not isinstance(expected, (str, bytes))
        else ()
    )
    for item in actual:
        if any(_contains_expected(item, candidate) for candidate in expected_items):
            continue
        if isinstance(item, Mapping):
            kind = str(item.get("type") or "")
            source = str(item.get("source") or "")
            target = str(item.get("target") or "")
            if (
                allow_docker_socket
                and source == "/var/run/docker.sock"
                and target == "/var/run/docker.sock"
                and item.get("read_only") is not True
            ):
                continue
            if kind in {"bind", "tmpfs"} or source == "/var/run/docker.sock":
                return True
        elif isinstance(item, str):
            source = item.split(":", 1)[0]
            if source.startswith("/") or source.startswith("."):
                return True
    return False


def _contains_expected(actual: object, expected: object) -> bool:
    """Compare Compose-normalized data while allowing unrelated service keys."""

    if isinstance(expected, Mapping):
        return isinstance(actual, Mapping) and all(
            key in actual and _contains_expected(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, Sequence) and not isinstance(expected, (str, bytes)):
        if not isinstance(actual, Sequence) or isinstance(actual, (str, bytes)):
            return False
        # Runtime mount order is not semantic after Compose normalization; other
        # authored sequences retain exact order.
        if expected and all(isinstance(item, Mapping) for item in expected):
            return all(
                any(_contains_expected(candidate, item) for candidate in actual)
                for item in expected
            )
        return list(actual) == list(expected)
    return actual == expected


def effective_runtime_contract_issues(
    payload: object,
    realization: DeploymentRealizationSpec,
    *,
    profile: RuntimeMaterializationProfile,
    validated_service_volumes: Mapping[str, Sequence[object]] | None = None,
) -> tuple[RuntimeMaterializationIssue, ...]:
    """Compare a read-only effective Compose model with the admitted runtime.

    ``validated_service_volumes`` contains exact generated mounts already
    checked by the stateful realization validator.  They are admitted graph
    edges rather than ``runtime.mounts`` and must therefore participate in the
    expected authority set without being mistaken for an undeclared host bind.
    """

    from aptl.core.deployment._compose_node_generation import _operational_config

    services = payload.get("services") if isinstance(payload, Mapping) else None
    if not isinstance(services, Mapping):
        return (
            _issue(
                "provision.graph",
                "runtime",
                profile,
                "effective Compose model has no services map",
            ),
        )
    image_addresses = {image.address for image in realization.images}
    authority_addresses = {
        admission.node_address
        for admission in realization.docker_authority_admissions
    }
    issues: list[RuntimeMaterializationIssue] = []
    for node in realization.nodes:
        if node.address not in image_addresses or not node.service_name:
            continue
        service = services.get(node.service_name)
        if not isinstance(service, Mapping):
            issues.append(
                _issue(
                    node.address,
                    "runtime",
                    profile,
                    "image-backed node is absent from the effective Compose model",
                )
            )
            continue
        expected = _operational_config(node.runtime)
        validated_volumes = (
            validated_service_volumes.get(node.service_name, ())
            if validated_service_volumes is not None
            else ()
        )
        if validated_volumes:
            expected["volumes"] = [
                *expected.get("volumes", []),
                *validated_volumes,
            ]
        for compose_field, value in expected.items():
            portable_field = _RUNTIME_COMPOSE_FIELDS.get(compose_field)
            if portable_field is None:
                continue
            if not _contains_expected(service.get(compose_field), value):
                issues.append(
                    _issue(
                        node.address,
                        portable_field,
                        profile,
                        "effective Compose model does not preserve the authored value",
                    )
                )
        for compose_field in _COMPOSE_AUTHORITY_FIELDS:
            if compose_field not in service or compose_field in expected:
                continue
            if compose_field == "volumes" and not _undeclared_mount_authority(
                service.get(compose_field),
                expected.get(compose_field),
                allow_docker_socket=node.address in authority_addresses,
            ):
                continue
            issues.append(
                _issue(
                    node.address,
                    _compose_authority_field(compose_field),
                    profile,
                    "effective Compose model adds undeclared runtime authority",
                )
            )
    return tuple(issues)


__all__ = [
    "SHARED_DOCKER_PROFILE",
    "RuntimeContainmentEvidence",
    "RuntimeMaterializationIssue",
    "RuntimeMaterializationProfile",
    "effective_runtime_contract_issues",
    "qualify_runtime_materialization",
]
