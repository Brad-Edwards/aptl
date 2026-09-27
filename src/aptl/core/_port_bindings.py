"""What the Docker daemon says this project already publishes.

Port resolution probes the host to find a free port, but a container this
project already started is holding its own published port: probing that port
would find it busy and remap a service away from the address the operator was
already given. This module reads the daemon's own view of the running project
so resolution can keep a binding that is already ours.

Split out of ``host_ports`` so neither the daemon-inspection half nor the
compose-parsing and probing half outgrows a file a reader can hold in their
head.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

# (compose service, container port, protocol) -> published host port.
PortBindingKey = tuple[str, int, str]


def _container_identity(entry: object) -> tuple[str, str] | None:
    """Return a Compose service and container name from one ``ps`` entry."""
    if not isinstance(entry, dict):
        return None
    service = str(entry.get("Service") or "")
    name = str(entry.get("Name") or "").lstrip("/")
    return (service, name) if service and name else None


def _binding_host_ports(bindings: object) -> set[int]:
    """Return valid, non-zero host ports from an inspected port binding."""
    host_ports: set[int] = set()
    if not isinstance(bindings, list):
        return host_ports
    for binding in bindings:
        try:
            host_port = int(binding.get("HostPort", 0))
        except (AttributeError, TypeError, ValueError):
            continue
        if host_port:
            host_ports.add(host_port)
    return host_ports


def _inspected_port_candidates(
    backend: DeploymentBackend, service: str, name: str
) -> dict[PortBindingKey, set[int]]:
    """Return valid published-port candidates for one running container."""
    try:
        info = backend.container_inspect(name)
    except Exception:
        return {}
    ports: dict[object, object] = {}
    if isinstance(info, dict):
        inspected = (info.get("NetworkSettings") or {}).get("Ports") or {}
        if isinstance(inspected, dict):
            ports = inspected

    candidates: dict[PortBindingKey, set[int]] = {}
    for container_port_proto, bindings in ports.items():
        port_raw, _, proto = str(container_port_proto).partition("/")
        try:
            container_port = int(port_raw)
        except ValueError:
            continue
        host_ports = _binding_host_ports(bindings)
        if host_ports:
            candidates[(service, container_port, proto or "tcp")] = host_ports
    return candidates


def project_port_bindings(
    backend: DeploymentBackend,
) -> dict[PortBindingKey, int]:
    """Return published host ports already owned by this Compose project.

    Docker exposes the same binding once for IPv4 and once for IPv6.  A key is
    returned only when every address agrees on one host port; ambiguous runtime
    state falls back to the normal availability probe.
    """
    try:
        containers = backend.container_list(all_containers=False)
    except Exception:
        return {}

    candidates: dict[PortBindingKey, set[int]] = {}
    for entry in containers:
        identity = _container_identity(entry)
        if identity is None:
            continue
        service, name = identity
        for key, host_ports in _inspected_port_candidates(
            backend, service, name
        ).items():
            candidates.setdefault(key, set()).update(host_ports)
    # Directly-created operator relays are receipt-owned project containers,
    # but ``docker compose ps`` cannot list them. Resolve their semantic names
    # through the backend's receipt-verified inspection path so a retry keeps
    # the relay's own publication instead of treating it as a foreign holder.
    from aptl.core.deployment._operator_access_endpoints import (
        OPERATOR_ACCESS_ENDPOINTS,
    )

    for endpoint in OPERATOR_ACCESS_ENDPOINTS.values():
        key = (endpoint.relay_container, endpoint.listen_port, "tcp")
        owned = _inspected_port_candidates(
            backend, endpoint.relay_container, endpoint.relay_container
        )
        if key in owned:
            candidates.setdefault(key, set()).update(owned[key])
    return {
        key: next(iter(host_ports))
        for key, host_ports in candidates.items()
        if len(host_ports) == 1
    }
