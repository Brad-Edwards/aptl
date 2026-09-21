"""Daemon-observed ports, capabilities, and network listeners."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _disclose
from aptl.backends._runtime_concern_excess import (
    _INIT_CAPABILITY_BASELINE,
    _capabilities_corroborate,
    _has_undeclared_ports,
    _normalized_capabilities,
    _port_entry_matches,
    _realized_scope_matches_declared,
    _runs_init,
    _sensitivity,
)
from aptl.core.deployment.realization import LOOPBACK_HOST_IP

if TYPE_CHECKING:
    from aptl.core.deployment._proc_net_listeners import ContainerListeners
    from aptl.core.deployment.backend import DeploymentBackend


def observe_published_ports(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared host ports only when all daemon bindings agree."""

    network = runtime.network
    declared_ports = tuple(network.published_ports) if network is not None else ()
    bindings = _port_bindings(info)
    if _has_undeclared_ports(bindings, declared_ports) or not declared_ports:
        return None
    disclosed = [
        port.model_dump(mode="json", by_alias=True)
        for port in declared_ports
        if _port_binding_present(port, bindings)
    ]
    return _disclose("published-ports", disclosed) if disclosed else None


def _port_bindings(info: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return ``HostConfig.PortBindings`` as a mapping, or empty."""

    host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
    bindings = (
        host_config.get("PortBindings") if isinstance(host_config, Mapping) else None
    )
    return bindings if isinstance(bindings, Mapping) else {}


def _port_binding_present(port: object, bindings: Mapping[str, Any]) -> bool:
    """Return whether the container realized one declared port binding."""

    key = f"{getattr(port, 'container_port', '')}/{getattr(port, 'protocol', 'tcp')}"
    entries = bindings.get(key)
    if not isinstance(entries, Sequence):
        return False
    expected_ip = getattr(port, "host_ip", "") or LOOPBACK_HOST_IP
    host_port = getattr(port, "host_port", None)
    expected_port = str(host_port) if host_port is not None else None
    return any(
        _port_entry_matches(entry, expected_ip, expected_port)
        for entry in entries
        if isinstance(entry, Mapping)
    )


def observe_capabilities(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose a capability policy only when daemon grants corroborate it."""

    policy = runtime.linux_capabilities
    if policy is None:
        return None
    declared = policy.model_dump(mode="json", by_alias=True)
    unrealizable = bool(
        declared.get("required")
        or declared.get("effective")
        or declared.get("process_overrides")
    )
    host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
    granted = _normalized_capabilities(
        host_config.get("CapAdd") if isinstance(host_config, Mapping) else None
    )
    dropped = _normalized_capabilities(
        host_config.get("CapDrop") if isinstance(host_config, Mapping) else None
    )
    baseline = _INIT_CAPABILITY_BASELINE if _runs_init(runtime) else frozenset()
    corroborated = not unrealizable and _capabilities_corroborate(
        declared, granted, dropped, baseline
    )
    return _disclose("linux-capabilities", declared) if corroborated else None


def observe_service_listeners(
    backend: DeploymentBackend,
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared listeners only when the trusted netns read agrees."""

    declared = runtime.service_listeners
    observed = backend.observe_container_listeners(container_name) if declared else None
    if observed is None:
        return None
    disclosed = [
        listener.model_dump(mode="json", by_alias=True)
        for listener in declared
        if _listener_present(listener, observed)
    ]
    return _disclose("service-listeners", disclosed) if disclosed else None


def _listener_present(listener: object, observed: ContainerListeners) -> bool:
    """Return whether the trusted observation corroborates one listener."""

    protocol = _sensitivity(getattr(listener, "protocol", ""))
    if protocol == "unix":
        socket_path = getattr(listener, "socket_path", "")
        return bool(socket_path) and socket_path in observed.unix_socket_paths
    return _network_listener_present(listener, protocol, observed)


def _network_listener_present(
    listener: object, protocol: str, observed: ContainerListeners
) -> bool:
    """Return whether a trusted read corroborates one tcp/udp listener."""

    port = getattr(listener, "port", None)
    declared_address = getattr(listener, "address", "")
    if port is None or declared_address.startswith("$"):
        return False
    declared_port = int(port)
    return any(
        socket_protocol == protocol
        and socket_port == declared_port
        and _realized_scope_matches_declared(socket_address, declared_address)
        for socket_protocol, socket_address, socket_port in observed.sockets
    )


__all__ = (
    "observe_capabilities",
    "observe_published_ports",
    "observe_service_listeners",
)
