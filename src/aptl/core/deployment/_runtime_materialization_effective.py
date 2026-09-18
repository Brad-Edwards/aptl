"""Validate effective Compose authority against admitted runtime state."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeGuard

from aptl.core.deployment._runtime_materialization_types import (
    RuntimeMaterializationIssue,
    RuntimeMaterializationProfile,
    materialization_issue,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec

_DOCKER_SOCKET = "/var/run/docker.sock"
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


def _is_sequence(value: object) -> TypeGuard[Sequence[object]]:
    """Whether a value is a non-text sequence."""

    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _mapping_contains(actual: object, expected: Mapping[object, object]) -> bool:
    """Compare a normalized mapping while allowing unrelated keys."""

    return isinstance(actual, Mapping) and all(
        key in actual and _contains_expected(actual[key], value)
        for key, value in expected.items()
    )


def _sequence_contains(actual: object, expected: Sequence[object]) -> bool:
    """Compare exact sequences or unordered sequences of mappings."""

    if not _is_sequence(actual):
        return False
    if expected and all(isinstance(item, Mapping) for item in expected):
        return all(
            any(_contains_expected(candidate, item) for candidate in actual)
            for item in expected
        )
    return list(actual) == list(expected)


def _contains_expected(actual: object, expected: object) -> bool:
    """Compare Compose-normalized data while allowing unrelated service keys."""

    if isinstance(expected, Mapping):
        return _mapping_contains(actual, expected)
    if _is_sequence(expected):
        return _sequence_contains(actual, expected)
    return actual == expected


def _undeclared_mapping_mount(
    item: Mapping[object, object],
    *,
    allow_docker_socket: bool,
) -> bool:
    """Whether one mapping-form mount adds undeclared authority."""

    kind = str(item.get("type") or "")
    source = str(item.get("source") or "")
    target = str(item.get("target") or "")
    admitted_socket = (
        allow_docker_socket
        and source == _DOCKER_SOCKET
        and target == _DOCKER_SOCKET
        and item.get("read_only") is not True
    )
    return not admitted_socket and (
        kind in {"bind", "tmpfs"} or source == _DOCKER_SOCKET
    )


def _undeclared_mount_item(
    item: object,
    expected_items: Sequence[object],
    *,
    allow_docker_socket: bool,
) -> bool:
    """Whether one effective mount adds undeclared boundary authority."""

    if any(_contains_expected(item, candidate) for candidate in expected_items):
        return False
    if isinstance(item, Mapping):
        return _undeclared_mapping_mount(
            item,
            allow_docker_socket=allow_docker_socket,
        )
    source = item.split(":", 1)[0] if isinstance(item, str) else ""
    return source.startswith(("/", "."))


def _undeclared_mount_authority(
    actual: object,
    expected: object,
    *,
    allow_docker_socket: bool,
) -> bool:
    """Whether an effective service adds a bind, tmpfs, or socket mount."""

    if not _is_sequence(actual):
        return bool(actual)
    expected_items = expected if _is_sequence(expected) else ()
    return any(
        _undeclared_mount_item(
            item,
            expected_items,
            allow_docker_socket=allow_docker_socket,
        )
        for item in actual
    )


def _expected_service_config(
    node: object,
    validated_service_volumes: Mapping[str, Sequence[object]] | None,
) -> dict[str, object]:
    """Return authored runtime plus already-validated graph-owned volumes."""

    from aptl.core.deployment._compose_node_generation import _operational_config

    expected = _operational_config(getattr(node, "runtime", None))
    service_name = str(getattr(node, "service_name", ""))
    validated = (
        validated_service_volumes.get(service_name, ())
        if validated_service_volumes is not None
        else ()
    )
    if validated:
        expected["volumes"] = [*expected.get("volumes", []), *validated]
    return expected


def _authored_value_issues(
    node: object,
    service: Mapping[object, object],
    expected: Mapping[str, object],
    profile: RuntimeMaterializationProfile,
) -> list[RuntimeMaterializationIssue]:
    """Return effective values that do not preserve authored settings."""

    return [
        materialization_issue(
            str(getattr(node, "address", "")),
            portable_field,
            profile,
            "effective Compose model does not preserve the authored value",
        )
        for compose_field, value in expected.items()
        if (portable_field := _RUNTIME_COMPOSE_FIELDS.get(compose_field)) is not None
        and not _contains_expected(service.get(compose_field), value)
    ]


def _authority_field_issues(
    node: object,
    service: Mapping[object, object],
    expected: Mapping[str, object],
    authority_addresses: set[str],
    profile: RuntimeMaterializationProfile,
) -> list[RuntimeMaterializationIssue]:
    """Return effective authority fields absent from the admitted contract."""

    address = str(getattr(node, "address", ""))
    issues: list[RuntimeMaterializationIssue] = []
    for compose_field in _COMPOSE_AUTHORITY_FIELDS:
        if compose_field not in service or compose_field in expected:
            continue
        allowed_volumes = (
            compose_field == "volumes"
            and not _undeclared_mount_authority(
                service.get(compose_field),
                expected.get(compose_field),
                allow_docker_socket=address in authority_addresses,
            )
        )
        if not allowed_volumes:
            issues.append(
                materialization_issue(
                    address,
                    _compose_authority_field(compose_field),
                    profile,
                    "effective Compose model adds undeclared runtime authority",
                )
            )
    return issues


def _service_issues(
    node: object,
    services: Mapping[object, object],
    authority_addresses: set[str],
    profile: RuntimeMaterializationProfile,
    validated_service_volumes: Mapping[str, Sequence[object]] | None,
) -> list[RuntimeMaterializationIssue]:
    """Compare one image-backed service with its admitted contract."""

    address = str(getattr(node, "address", ""))
    service = services.get(getattr(node, "service_name", None))
    if not isinstance(service, Mapping):
        return [
            materialization_issue(
                address,
                "runtime",
                profile,
                "image-backed node is absent from the effective Compose model",
            )
        ]
    expected = _expected_service_config(node, validated_service_volumes)
    issues = _authored_value_issues(node, service, expected, profile)
    issues.extend(
        _authority_field_issues(
            node,
            service,
            expected,
            authority_addresses,
            profile,
        )
    )
    return issues


def effective_runtime_contract_issues(
    payload: object,
    realization: DeploymentRealizationSpec,
    *,
    profile: RuntimeMaterializationProfile,
    validated_service_volumes: Mapping[str, Sequence[object]] | None = None,
) -> tuple[RuntimeMaterializationIssue, ...]:
    """Compare a read-only effective Compose model with the admitted runtime."""

    services = payload.get("services") if isinstance(payload, Mapping) else None
    if not isinstance(services, Mapping):
        return (
            materialization_issue(
                "provision.graph",
                "runtime",
                profile,
                "effective Compose model has no services map",
            ),
        )
    image_addresses = {image.address for image in realization.images}
    authority_addresses = {
        admission.node_address for admission in realization.docker_authority_admissions
    }
    issues = [
        issue
        for node in realization.nodes
        if node.address in image_addresses and node.service_name
        for issue in _service_issues(
            node,
            services,
            authority_addresses,
            profile,
            validated_service_volumes,
        )
    ]
    return tuple(issues)
