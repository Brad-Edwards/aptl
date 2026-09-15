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

from aptl.backends._runtime_concern_disclosure import _PROTECTED, _disclose, _record
from aptl.backends._runtime_concern_excess import (
    _INIT_CAPABILITY_BASELINE,
    _normalized_capabilities,
)
from aptl.backends._runtime_mount_observation import (
    _observe_forwarding_agents,
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
_PROCESS_RESOURCE_LIMITS_PATH = CONCERN_PAYLOAD_PATH["process-resource-limits"]
_LOCAL_CONTROL_INTERFACES_PATH = CONCERN_PAYLOAD_PATH[
    "runtime-local-control-interfaces"
]
_LOCAL_IDENTITY_PATH = CONCERN_PAYLOAD_PATH["runtime-local-identity"]
_DEPENDENCY_MANIFESTS_PATH = CONCERN_PAYLOAD_PATH["runtime-dependency-manifests"]

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

    if runtime_declared:
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
        lambda: _observe_forwarding_agents(info, runtime),
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
    """Return the daemon's effective restart policy, including APTL defaults."""

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

    kind = str(getattr(interface.kind, "value", interface.kind))
    access = str(getattr(interface.access, "value", interface.access))
    source = interface.bind_source or interface.path
    supported = (
        kind == "unix_socket"
        and access in {"read_only", "read_write"}
        and interface.path == "/var/run/docker.sock"
        and source == "/var/run/docker.sock"
        and not interface.protocol
    )
    return supported and any(
        isinstance(mount, Mapping)
        and mount.get("Type") == "bind"
        and mount.get("Source") == source
        and mount.get("Destination") == interface.path
        and bool(mount.get("RW")) == (access == "read_write")
        for mount in mounts
    )


# --------------------------------------------------------------------------- #
# runtime-environment
# --------------------------------------------------------------------------- #


def _observe_environment(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared env variables carrying their realized container values."""

    declared = runtime.environment
    if not declared:
        return None
    realized = _container_environment(info)
    records = [
        record
        for variable in declared
        if (record := _realized_environment_record(variable, realized)) is not None
    ]
    return _disclose("runtime-environment", records) if records else None


def _realized_environment_record(
    variable: object, realized: Mapping[str, str]
) -> dict[str, object] | None:
    """Project one declared variable through its realized value boundary."""

    name = getattr(variable, "name", "")
    if not name:
        return None
    record = variable.model_dump(mode="json", by_alias=True)
    classification = record.get("value_classification")
    declared_value = record.get("value")
    if classification not in _PROTECTED and not declared_value:
        realized_value = realized.get(name)
        if realized_value:
            record["value"] = realized_value
        return record
    if name not in realized:
        return None
    record["value"] = "" if classification in _PROTECTED else realized[name]
    return record


def _container_environment(info: Mapping[str, Any]) -> dict[str, str]:
    """Parse the realized container's ``Config.Env`` into a name -> value map."""

    config = info.get("Config") if isinstance(info, Mapping) else None
    entries = config.get("Env") if isinstance(config, Mapping) else None
    realized: dict[str, str] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, str) and "=" in entry:
                name, _, value = entry.partition("=")
                realized[name] = value
    return realized


# --------------------------------------------------------------------------- #
# published-ports
# --------------------------------------------------------------------------- #


__all__ = [
    "_INIT_CAPABILITY_BASELINE",
    "_listener_present",
    "_normalized_capabilities",
    "observe_runtime_concerns",
]
