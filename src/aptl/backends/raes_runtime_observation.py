"""Provider-observed disclosure of runtime realization concerns (#876/#992).

Daemon metadata supplies container policy, environment, mounts, capabilities,
ports, listeners, forwarding agents, and control interfaces. Bounded guest
queries supply facts absent from daemon state. Each observer discloses a value
only when realized state corroborates it and otherwise omits the concern so
RAES rejects an exact requirement. These paths add no scenario observer.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from raes.runtime_configuration import RuntimeConfiguration
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._runtime_concern_disclosure import _disclose, _record
from aptl.backends._raes_runtime_environment_observation import (
    observe_environment as _observe_environment,
)
from aptl.backends._runtime_concern_excess import (
    _INIT_CAPABILITY_BASELINE,
    _normalized_capabilities,
)
from aptl.backends._runtime_mount_observation import (
    _observe_mounts,
)
from aptl.backends._raes_runtime_network_observation import (
    _listener_present,
    observe_capabilities as _observe_capabilities,
    observe_published_ports as _observe_published_ports,
    observe_service_listeners as _observe_service_listeners,
)
from aptl.backends.raes_runtime_guest_observation import (
    observe_dependency_manifests,
    observe_filesystem_inventory,
    observe_local_identity,
    observe_packages,
    observe_process_resource_limits,
    observe_service_manager_units,
)
from aptl.utils.logging import get_logger
from aptl.core.deployment._forwarding_agent_realization import (
    forwarding_agents_configured,
)

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext

log = get_logger("realization-observe")

_ENVIRONMENT_PATH = CONCERN_PAYLOAD_PATH["runtime-environment"]
_MOUNTS_PATH = CONCERN_PAYLOAD_PATH["runtime-mounts"]
_CAPABILITIES_PATH = CONCERN_PAYLOAD_PATH["linux-capabilities"]
_PUBLISHED_PORTS_PATH = CONCERN_PAYLOAD_PATH["published-ports"]
_SERVICE_LISTENERS_PATH = CONCERN_PAYLOAD_PATH["service-listeners"]
_FORWARDING_AGENTS_PATH = CONCERN_PAYLOAD_PATH["forwarding-agents"]
_PACKAGES_PATH = CONCERN_PAYLOAD_PATH["runtime-packages"]
_FILESYSTEM_INVENTORY_PATH = CONCERN_PAYLOAD_PATH["runtime-filesystem-inventory"]
_SERVICE_MANAGER_UNITS_PATH = CONCERN_PAYLOAD_PATH["runtime-service-manager-units"]
_RESTART_POLICY_PATH = CONCERN_PAYLOAD_PATH["runtime-restart-policy"]
_MEMORY_LIMIT_PATH = CONCERN_PAYLOAD_PATH["runtime-node-memory-limit"]
_ENTRYPOINT_PATH = CONCERN_PAYLOAD_PATH["runtime-container-entrypoint"]
_COMMAND_PATH = CONCERN_PAYLOAD_PATH["runtime-container-command"]
_AUTOREMOVE_PATH = CONCERN_PAYLOAD_PATH["runtime-container-autoremove"]
_CONTAINER_DAEMON_FIELDS = {
    "cgroup_parent": "runtime-container-cgroup-parent",
    "device_cgroup_rules": "runtime-container-device-cgroup-rules",
    "devices": "runtime-container-devices",
    "dns": "runtime-container-dns",
    "dns_options": "runtime-container-dns-options",
    "dns_search": "runtime-container-dns-search",
    "extra_hosts": "runtime-container-extra-hosts",
    "group_add": "runtime-container-group-add",
    "init_process": "runtime-container-init-process",
    "log_driver": "runtime-container-log-driver",
    "log_options": "runtime-container-log-options",
    "namespaces": "runtime-container-namespaces",
    "privileged": "runtime-container-privileged",
    "read_only_rootfs": "runtime-container-read-only-rootfs",
    "runtime_name": "runtime-container-runtime-name",
    "seccomp_profile": "runtime-container-seccomp-profile",
    "security_opt": "runtime-container-security-opt",
    "shm_size": "runtime-container-shm-size",
}
_PROCESS_RESOURCE_LIMITS_PATH = CONCERN_PAYLOAD_PATH["process-resource-limits"]
_LOCAL_CONTROL_INTERFACES_PATH = CONCERN_PAYLOAD_PATH[
    "runtime-local-control-interfaces"
]
_LOCAL_IDENTITY_PATH = CONCERN_PAYLOAD_PATH["runtime-local-identity"]
_DEPENDENCY_MANIFESTS_PATH = CONCERN_PAYLOAD_PATH["runtime-dependency-manifests"]
_DOCKER_SOCKET = "/var/run/docker.sock"

# The excess-detection, scope, and init-baseline helpers this module's observers
# rely on live in :mod:`aptl.backends._runtime_concern_excess`; they are imported
# above so the disclosure and completeness logic stays in one place.


def observe_runtime_concerns(
    backend: "DeploymentBackend",
    container_name: str | None,
    info: Mapping[str, Any],
    declared_runtime: RuntimeConfiguration | None,
    *,
    observe_backend_process_defaults: bool = False,
    observation_context: DeploymentObservationContext | None = None,
) -> dict[tuple[str, ...], object]:
    """Return the disclosed runtime concerns a realized node declares.

    Keyed by ``CONCERN_PAYLOAD_PATH`` tuple. A concern APTL cannot be seen to
    have realized is absent, so the gate reads an omission (a rejected EXACT
    declaration) rather than an echo of the plan.
    """

    concerns: dict[tuple[str, ...], object] = {}
    if container_name:
        runtime = declared_runtime or RuntimeConfiguration()
        _record_container_policy(
            concerns,
            container_name,
            info,
            runtime,
            declared_runtime is not None,
            observation_context,
        )
        _record_process_limits(
            concerns,
            backend,
            container_name,
            runtime,
            observe_backend_process_defaults,
        )
        _record_daemon_inventory(concerns, backend, container_name, info, runtime)
        _record_guest_inventory(concerns, backend, container_name, runtime)
    return concerns


def _record_container_policy(
    concerns: dict[tuple[str, ...], object],
    container_name: str,
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    runtime_declared: bool,
    observation_context: DeploymentObservationContext | None,
) -> None:
    """Record policy controlled directly by the container daemon."""

    policy = runtime.operational_policy
    restart = policy.restart if policy is not None else None
    restart_value = str(getattr(restart, "value", restart) or "")
    if runtime_declared and restart_value not in {"", "unknown"}:
        _record(concerns, _RESTART_POLICY_PATH, lambda: _observe_restart_policy(info))
    _record(
        concerns,
        _MEMORY_LIMIT_PATH,
        lambda: _observe_memory_limit(info, runtime),
    )
    _record(
        concerns,
        _ENTRYPOINT_PATH,
        lambda: _observe_container_sequence(
            info,
            runtime,
            inspect_field="Entrypoint",
            runtime_field="entrypoint",
            concern_kind="runtime-container-entrypoint",
        ),
    )
    _record(
        concerns,
        _COMMAND_PATH,
        lambda: _observe_container_sequence(
            info,
            runtime,
            inspect_field="Cmd",
            runtime_field="command",
            concern_kind="runtime-container-command",
        ),
    )
    _record(
        concerns,
        _AUTOREMOVE_PATH,
        lambda: _observe_autoremove(
            container_name,
            info,
            runtime,
            observation_context,
        ),
    )
    for field, concern_kind in _CONTAINER_DAEMON_FIELDS.items():
        _record(
            concerns,
            CONCERN_PAYLOAD_PATH[concern_kind],
            lambda field=field, concern_kind=concern_kind: _observe_container_field(
                info,
                runtime,
                field=field,
                concern_kind=concern_kind,
            ),
        )


def _record_process_limits(
    concerns: dict[tuple[str, ...], object],
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
    observe_defaults: bool,
) -> None:
    """Record effective process limits when selected or explicitly declared."""

    policy = runtime.operational_policy
    limits = policy.resource_limits if policy is not None else None
    if (
        limits is not None and getattr(limits, "process_limits", ())
    ) or observe_defaults:
        _record(
            concerns,
            _PROCESS_RESOURCE_LIMITS_PATH,
            lambda: observe_process_resource_limits(backend, container_name, runtime),
        )


def _record_daemon_inventory(
    concerns: dict[tuple[str, ...], object],
    backend: "DeploymentBackend",
    container_name: str,
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> None:
    """Record declared concerns that the daemon or kernel can corroborate."""

    _record(
        concerns,
        _LOCAL_CONTROL_INTERFACES_PATH,
        lambda: _observe_local_control_interfaces(info, runtime),
    )
    _record(
        concerns,
        _ENVIRONMENT_PATH,
        lambda: _observe_environment(info, runtime),
    )
    _record(
        concerns,
        _PUBLISHED_PORTS_PATH,
        lambda: _observe_published_ports(info, runtime),
    )
    _record(
        concerns,
        _CAPABILITIES_PATH,
        lambda: _observe_capabilities(info, runtime),
    )
    _record(concerns, _MOUNTS_PATH, lambda: _observe_mounts(info, runtime))
    _record(
        concerns,
        _SERVICE_LISTENERS_PATH,
        lambda: _observe_service_listeners(backend, container_name, runtime),
    )
    _record(
        concerns,
        _FORWARDING_AGENTS_PATH,
        lambda: _observe_forwarding_agents(backend, container_name, runtime),
    )


def _observe_forwarding_agents(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose agents only after their in-world configuration verifies."""

    if not forwarding_agents_configured(backend, container_name, runtime):
        return None
    return _disclose(
        "forwarding-agents",
        [
            agent.model_dump(mode="json", by_alias=True)
            for agent in runtime.forwarding_agents
        ],
    )


def _record_guest_inventory(
    concerns: dict[tuple[str, ...], object],
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> None:
    """Record declared concerns available only through bounded guest reads."""

    _record(
        concerns,
        _LOCAL_IDENTITY_PATH,
        lambda: observe_local_identity(backend, container_name, runtime),
    )
    _record(
        concerns,
        _DEPENDENCY_MANIFESTS_PATH,
        lambda: observe_dependency_manifests(backend, container_name, runtime),
    )
    _record(
        concerns,
        _PACKAGES_PATH,
        lambda: observe_packages(backend, container_name, runtime),
    )
    _record(
        concerns,
        _FILESYSTEM_INVENTORY_PATH,
        lambda: observe_filesystem_inventory(backend, container_name, runtime),
    )
    _record(
        concerns,
        _SERVICE_MANAGER_UNITS_PATH,
        lambda: observe_service_manager_units(backend, container_name, runtime),
    )


# --------------------------------------------------------------------------- #
# daemon-owned container policy
# --------------------------------------------------------------------------- #


def _host_config(info: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return daemon HostConfig metadata as a mapping."""

    value = info.get("HostConfig") if isinstance(info, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _container_config(info: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return daemon container Config metadata as a mapping."""

    value = info.get("Config") if isinstance(info, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _observe_restart_policy(info: Mapping[str, Any]) -> object | None:
    """Return the daemon's effective explicitly selected restart policy."""

    policy = _host_config(info).get("RestartPolicy")
    name = policy.get("Name") if isinstance(policy, Mapping) else None
    if not isinstance(name, str) or not name:
        return None
    return _disclose("runtime-restart-policy", name.replace("-", "_"))


def _observe_memory_limit(
    info: Mapping[str, Any], runtime: RuntimeConfiguration
) -> object | None:
    """Return the configured byte limit when the SDL selected that dimension."""

    policy = runtime.operational_policy
    limits = policy.resource_limits if policy is not None else None
    if limits is None or limits.memory is None:
        return None
    value = _host_config(info).get("Memory")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return _disclose("runtime-node-memory-limit", value)


def _observe_container_sequence(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    *,
    inspect_field: str,
    runtime_field: str,
    concern_kind: str,
) -> object | None:
    """Disclose a declared command sequence read from container metadata."""

    container = runtime.container
    declared = (
        getattr(container, runtime_field, None) if container is not None else None
    )
    if not declared:
        return None
    value = _container_config(info).get(inspect_field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return _disclose(concern_kind, value)


def _observe_autoremove(
    container_name: str,
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    observation_context: DeploymentObservationContext | None,
) -> object | None:
    """Corroborate retained or verified-removed container lifecycle state."""

    container = runtime.container
    declared = getattr(container, "autoremove", None) if container is not None else None
    if declared is None:
        return None
    expects_removal = (
        declared
        if isinstance(declared, bool)
        else isinstance(declared, str)
        and declared.strip().lower() in {"true", "1", "yes"}
    )
    if expects_removal:
        value = bool(
            observation_context is not None
            and observation_context.autoremove_verified(container_name)
        )
        corroborated = value
    else:
        value = _host_config(info).get("AutoRemove")
        corroborated = isinstance(value, bool)
    return _disclose("runtime-container-autoremove", value) if corroborated else None


def _json_value(value: object) -> object:
    """Return the portable JSON value carried by a RAES model field."""

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, list):
        return [
            item.model_dump(mode="json", by_alias=True)
            if hasattr(item, "model_dump")
            else item
            for item in value
        ]
    return value


def _truthy(value: object) -> bool:
    """Normalize RAES bool-or-string runtime flags."""

    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}


def _container_field_was_selected(container: object, field: str) -> bool:
    """Retain explicit empty/false closed-scope selections."""

    return field in getattr(container, "model_fields_set", set())


def _observe_container_field(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    *,
    field: str,
    concern_kind: str,
) -> object | None:
    """Disclose one authored container field after exact daemon corroboration."""

    container = runtime.container
    if container is None or not _container_field_was_selected(container, field):
        return None
    declared = getattr(container, field)
    host = _host_config(info)
    corroborated = _container_field_matches(host, container, field, declared)
    return _disclose(concern_kind, _json_value(declared)) if corroborated else None


def _container_field_matches(
    host: Mapping[str, Any],
    container: object,
    field: str,
    declared: object,
) -> bool:
    """Compare one supported RAES container field with native HostConfig."""

    direct = _direct_container_field_match(host, field, declared)
    if direct is not None:
        return direct
    if field == "devices":
        return _devices_match(host, declared)
    if field == "extra_hosts":
        expected_hosts = [f"{item.hostname}:{item.address}" for item in declared or ()]
        return host.get("ExtraHosts") == expected_hosts
    if field == "namespaces":
        return _namespaces_match(host, declared)
    if field in {"seccomp_profile", "security_opt"}:
        return _security_options_match(host, container)
    if field == "log_driver":
        config = host.get("LogConfig")
        return isinstance(config, Mapping) and config.get("Type") == declared
    if field == "log_options":
        config = host.get("LogConfig")
        return isinstance(config, Mapping) and config.get("Config") == dict(
            declared or {}
        )
    if field == "init_process":
        return host.get("Init") is _truthy(getattr(declared, "enabled", None))
    return False


def _direct_container_field_match(
    host: Mapping[str, Any], field: str, declared: object
) -> bool | None:
    """Match scalar and list fields with direct HostConfig counterparts."""

    direct_fields = {
        "privileged": "Privileged",
        "read_only_rootfs": "ReadonlyRootfs",
        "shm_size": "ShmSize",
        "cgroup_parent": "CgroupParent",
        "runtime_name": "Runtime",
        "device_cgroup_rules": "DeviceCgroupRules",
        "group_add": "GroupAdd",
        "dns": "Dns",
        "dns_options": "DnsOptions",
        "dns_search": "DnsSearch",
    }
    native_field = direct_fields.get(field)
    if native_field is None:
        return None
    if field in {"privileged", "read_only_rootfs"}:
        expected = _truthy(declared)
    elif field in {
        "device_cgroup_rules",
        "group_add",
        "dns",
        "dns_options",
        "dns_search",
    }:
        expected = list(declared or ())
    else:
        expected = declared
    return host.get(native_field) == expected


def _devices_match(host: Mapping[str, Any], declared: object) -> bool:
    expected_devices = [
        {
            "PathOnHost": item.host_path,
            "PathInContainer": item.container_path,
            "CgroupPermissions": item.permissions,
        }
        for item in declared or ()
    ]
    return host.get("Devices") == expected_devices


def _namespaces_match(host: Mapping[str, Any], declared: object) -> bool:
    if getattr(declared, "network", None) is not None:
        return False
    for runtime_field, native_field in (
        ("pid", "PidMode"),
        ("ipc", "IpcMode"),
        ("userns", "UsernsMode"),
        ("uts", "UTSMode"),
        ("cgroup", "CgroupnsMode"),
    ):
        expected = getattr(declared, runtime_field, "")
        if expected and host.get(native_field) != expected:
            return False
    return True


def _security_options_match(host: Mapping[str, Any], container: object) -> bool:
    expected = set(getattr(container, "security_opt", ()) or ())
    seccomp = getattr(container, "seccomp_profile", "")
    if seccomp:
        expected.add(f"seccomp={seccomp}")
    native = host.get("SecurityOpt")
    if not isinstance(native, list) or not all(
        isinstance(item, str) for item in native
    ):
        return False
    allowed = set(expected)
    if _truthy(getattr(container, "privileged", None)):
        allowed.add("label=disable")
    return expected <= set(native) <= allowed


def _observe_local_control_interfaces(
    info: Mapping[str, Any], runtime: RuntimeConfiguration
) -> object | None:
    """Corroborate the canonical Docker socket from daemon mount metadata."""

    interfaces = tuple(runtime.local_control_interfaces)
    mounts = info.get("Mounts")
    corroborated = bool(
        interfaces
        and isinstance(mounts, list)
        and all(_local_control_interface_matches(item, mounts) for item in interfaces)
    )
    value = [item.model_dump(mode="json", by_alias=True) for item in interfaces]
    return (
        _disclose("runtime-local-control-interfaces", value) if corroborated else None
    )


def _local_control_interface_matches(interface: object, mounts: list[object]) -> bool:
    """Corroborate the canonical Docker socket in daemon mount metadata."""

    expected = _supported_local_control_interface(interface)
    return expected is not None and any(
        _local_control_mount_matches(mount, *expected) for mount in mounts
    )


def _supported_local_control_interface(interface: object) -> tuple[str, str] | None:
    """Return the admitted Docker socket source and access mode."""

    kind = str(getattr(interface.kind, "value", interface.kind))
    access = str(getattr(interface.access, "value", interface.access))
    source = interface.bind_source or interface.path
    supported = (
        kind == "unix_socket"
        and access in {"read_only", "read_write"}
        and interface.path == _DOCKER_SOCKET
        and source == _DOCKER_SOCKET
        and not interface.protocol
    )
    return (source, access) if supported else None


def _local_control_mount_matches(mount: object, source: str, access: str) -> bool:
    """Compare one daemon-observed bind mount to the admitted interface."""

    return bool(
        isinstance(mount, Mapping)
        and mount.get("Type") == "bind"
        and mount.get("Source") == source
        and mount.get("Destination") == _DOCKER_SOCKET
        and bool(mount.get("RW")) == (access == "read_write")
    )


# --------------------------------------------------------------------------- #
# runtime-environment
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# published-ports
# --------------------------------------------------------------------------- #


__all__ = [
    "_INIT_CAPABILITY_BASELINE",
    "_listener_present",
    "_normalized_capabilities",
    "observe_runtime_concerns",
]
