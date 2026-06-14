"""Snapshot endpoint registry (ADR-036).

A small annotation table that maps a known container name to the
display metadata, container-side target port, and (for SSH) user that
``RangeSnapshot.services`` and ``RangeSnapshot.ssh`` need. The registry
does NOT carry host-published port numbers — those live in
``docker-compose.yml`` and reach snapshot capture through
``ContainerSnapshot.ports`` (populated by
``DeploymentBackend.host_list_lab_containers`` per ADR-023). This module
exists so adding a new endpoint is a single registry edit instead of
three places (``snapshot.py``, ``docker-compose.yml``, downstream
consumers).

Per ADR-036:

- Host-published port comes from runtime inventory, not the registry.
- A registered container whose runtime ports don't expose the expected
  target port + protocol → endpoint is omitted (treated as unavailable,
  not raised as a validation exception that would fail the whole
  snapshot).
- ``RangeSnapshot.to_dict()`` remains the redaction boundary. The
  registry carries no credential material at all: ``ServiceEndpoint``
  still has a ``credentials`` field for backward on-the-wire shape,
  but its value is the dataclass default empty string and ADR-029's
  redactor masks it regardless. Credential ownership is out of scope
  per ADR-036 Non-Goals.
"""

from dataclasses import dataclass
from typing import Literal

from aptl.core.snapshot import (
    ContainerSnapshot,
    ServiceEndpoint,
    SSHEndpoint,
)

EndpointKind = Literal["service", "ssh"]

_SSH_KEY_PATH = "~/.ssh/aptl_lab_key"


@dataclass(frozen=True)
class EndpointRegistryEntry(object):
    """Stable lab-topology annotation for a single container endpoint.

    Two protocol-shaped fields are kept disjoint because they answer
    different questions:

    - ``url_scheme`` — the application-layer scheme baked into the
      service URL the user sees (``https``, ``http``, ``ssh``). Only
      required for ``kind="service"``; SSH endpoints render their own
      ``ssh -i ... user@host -p port`` command and do not surface a URL.
    - ``transport_protocol`` — the OSI-L4 transport that
      ``parse_host_port`` must match against the Docker port string
      (``tcp`` or ``udp``). Required for both kinds; defaults to ``tcp``
      because every endpoint shipped today is TCP, but a future UDP/SCTP
      endpoint sets it explicitly.

    Conflating the two would let an entry quietly resolve through the
    parser's TCP default while claiming an HTTPS URL — exactly the
    "target port + transport protocol" boundary ADR-036 names.

    ``ssh_user`` is required for ``kind="ssh"`` and unused for services.

    No ``credentials`` field. ``ServiceEndpoint.credentials`` is the
    on-the-wire shape, and ADR-029 redacts it at
    ``RangeSnapshot.to_dict()`` (the field-name redactor in
    ``aptl.utils.redaction`` matches ``credentials`` as sensitive). A
    literal value in the registry would be source-side dead data —
    masked at every serialization boundary — so the registry carries
    no credential material at all. Credential ownership and surfacing
    are out of scope per ADR-036 Non-Goals.
    """

    container_name: str
    display_name: str
    kind: EndpointKind
    target_port: int
    url_scheme: str | None = None
    transport_protocol: str = "tcp"
    ssh_user: str | None = None


ENDPOINT_REGISTRY: tuple[EndpointRegistryEntry, ...] = (
    EndpointRegistryEntry(
        container_name="aptl-wazuh-dashboard",
        display_name="Wazuh Dashboard",
        kind="service",
        # Compose publishes `443:5601` — the dashboard listens on 5601
        # inside the container (matches the image's own healthcheck:
        # `curl -ks https://localhost:5601`). The host-side 443 is the
        # value `parse_host_port` derives from runtime inventory.
        target_port=5601,
        url_scheme="https",
        transport_protocol="tcp",
    ),
    EndpointRegistryEntry(
        container_name="aptl-wazuh-indexer",
        display_name="Wazuh Indexer",
        kind="service",
        target_port=9200,
        url_scheme="https",
        transport_protocol="tcp",
    ),
    EndpointRegistryEntry(
        container_name="aptl-wazuh-manager",
        display_name="Wazuh API",
        kind="service",
        target_port=55000,
        url_scheme="https",
        transport_protocol="tcp",
    ),
    EndpointRegistryEntry(
        container_name="aptl-victim",
        display_name="Victim",
        kind="ssh",
        target_port=22,
        transport_protocol="tcp",
        ssh_user="labadmin",
    ),
    EndpointRegistryEntry(
        container_name="aptl-kali",
        display_name="Kali",
        kind="ssh",
        target_port=22,
        transport_protocol="tcp",
        ssh_user="kali",
    ),
    EndpointRegistryEntry(
        container_name="aptl-reverse",
        display_name="Reverse Engineering",
        kind="ssh",
        target_port=22,
        transport_protocol="tcp",
        ssh_user="labadmin",
    ),
    EndpointRegistryEntry(
        container_name="aptl-workstation",
        display_name="Workstation",
        kind="ssh",
        target_port=22,
        transport_protocol="tcp",
        ssh_user="labadmin",
    ),
)


def _parse_port_entry(entry: str) -> tuple[int, int, str] | None:
    """Parse one ``docker ps``-style port mapping string.

    Returns ``(host_port, target_port, protocol)`` for a published
    mapping (``<host_ip>:<host_port>-><target>/<proto>``), or ``None``
    for exposed-but-not-published (``22/tcp``), malformed entries, or
    anything we cannot confidently parse. Intentionally narrow — this
    is not a general Compose parser (ADR-036 anti-pattern guard).
    """
    result: tuple[int, int, str] | None = None
    if "->" in entry:
        left, right = entry.split("->", 1)
        # left is "<host_ip>:<host_port>"; right is "<target>/<proto>".
        if ":" in left and "/" in right:
            host_port_str = left.rsplit(":", 1)[1]
            target_port_str, protocol = right.split("/", 1)
            if host_port_str.isdigit() and target_port_str.isdigit():
                result = (
                    int(host_port_str),
                    int(target_port_str),
                    protocol.strip(),
                )
    return result


def parse_host_port(
    ports: list[str],
    target_port: int,
    protocol: str = "tcp",
) -> int | None:
    """Return the host-published port for *target_port* / *protocol*.

    Iterates the backend-normalized ``ContainerSnapshot.ports`` shape
    and returns the first match, or ``None`` if no published mapping
    exposes *target_port* with the requested *protocol*.
    """
    for entry in ports:
        parsed = _parse_port_entry(entry)
        if parsed is None:
            continue
        host_port, parsed_target, parsed_proto = parsed
        if parsed_target == target_port and parsed_proto == protocol:
            return host_port
    return None


def select_ssh_host(networks: dict[str, str]) -> str | None:
    """Pick a host-reachable IP for SSH from a container's network map.

    Lab target containers (kali, victim, workstation) sit only on
    ``internal: true`` networks — SAF-002 makes them internal to block
    target internet egress — so Docker publishes no host port for them
    and a ``localhost:<port>`` endpoint is unreachable. The host can
    still reach those containers directly by container IP over the
    bridge (``internal: true`` blocks container↔internet and
    cross-network traffic, not host↔container). Any of a container's
    bridge IPs is host-reachable; the lowest network name is chosen so
    a multi-homed container (kali spans three networks) resolves to a
    stable IP across snapshots. Blank IPs are skipped; ``None`` means
    no addressable interface (the caller omits the endpoint).
    """
    for net_name in sorted(networks):
        ip = networks[net_name]
        if ip:
            return ip
    return None


def _running(container: ContainerSnapshot) -> bool:
    """True if the container's status string indicates an up-and-running container."""
    return "Up" in container.status


def _container_index(
    containers: list[ContainerSnapshot],
) -> dict[str, ContainerSnapshot]:
    """Index the snapshot list by container name for O(1) registry lookups."""
    return {c.name: c for c in containers}


def build_service_endpoints(
    containers: list[ContainerSnapshot],
) -> list[ServiceEndpoint]:
    """Build ``ServiceEndpoint`` records from the registry + runtime ports."""
    by_name = _container_index(containers)
    endpoints: list[ServiceEndpoint] = []
    for entry in ENDPOINT_REGISTRY:
        if entry.kind != "service":
            continue
        container = by_name.get(entry.container_name)
        if container is None or not _running(container):
            continue
        # Registry invariant: kind="service" entries always carry a
        # url_scheme. The assert documents this for the type checker
        # without leaving an unreachable defensive branch.
        assert entry.url_scheme is not None
        host_port = parse_host_port(
            container.ports,
            entry.target_port,
            protocol=entry.transport_protocol,
        )
        if host_port is None:
            continue
        endpoints.append(
            ServiceEndpoint(
                name=entry.display_name,
                url=f"{entry.url_scheme}://localhost:{host_port}",
                host="localhost",
                port=host_port,
                protocol=entry.url_scheme,
                # No registry-side credential literal (see class docstring).
                # ``ServiceEndpoint.credentials`` defaults to empty; ADR-029
                # redacts the field at ``RangeSnapshot.to_dict()`` regardless.
            )
        )
    return endpoints


def _build_ssh_endpoint(
    entry: EndpointRegistryEntry, container: ContainerSnapshot
) -> SSHEndpoint | None:
    """Project one running SSH registry entry onto its reachable endpoint.

    Lab SSH targets sit on internal-only networks with no published host
    port (issue #293), so they are addressed by container IP — the host
    reaches them over the bridge — and the endpoint connects to the
    container-side target port directly, not a remapped host port.
    Returns ``None`` when the container has no host-reachable IP.
    """
    # Registry invariant: kind="ssh" entries always carry an ssh_user.
    # The assert documents this for the type checker without leaving an
    # unreachable defensive branch.
    assert entry.ssh_user is not None
    host = select_ssh_host(container.networks)
    if host is None:
        return None
    command = f"ssh -i {_SSH_KEY_PATH} {entry.ssh_user}@{host}"
    return SSHEndpoint(
        name=entry.display_name,
        host=host,
        port=entry.target_port,
        user=entry.ssh_user,
        key_path=_SSH_KEY_PATH,
        command=command,
    )


def build_ssh_endpoints(
    containers: list[ContainerSnapshot],
) -> list[SSHEndpoint]:
    """Build ``SSHEndpoint`` records from the registry + runtime ports."""
    by_name = _container_index(containers)
    endpoints: list[SSHEndpoint] = []
    for entry in ENDPOINT_REGISTRY:
        if entry.kind != "ssh":
            continue
        container = by_name.get(entry.container_name)
        if container is None or not _running(container):
            continue
        endpoint = _build_ssh_endpoint(entry, container)
        if endpoint is not None:
            endpoints.append(endpoint)
    return endpoints


# Short terminal target names (registry container name minus the
# ``aptl-`` prefix). The WebSocket relay validates an incoming container
# against this set before touching runtime inventory, so a new terminal
# target is a single registry edit — not a second hardcoded map
# (ADR-039).
_TERMINAL_CONTAINER_PREFIX = "aptl-"
TERMINAL_CONTAINER_NAMES: frozenset[str] = frozenset(
    entry.container_name.removeprefix(_TERMINAL_CONTAINER_PREFIX)
    for entry in ENDPOINT_REGISTRY
    if entry.kind == "ssh"
)


def terminal_ssh_endpoints(
    containers: list[ContainerSnapshot],
) -> dict[str, SSHEndpoint]:
    """Map terminal short-name → reachable ``SSHEndpoint`` (ADR-039).

    The small registry projection the operator terminal relay consumes to
    derive host/user/port from runtime inventory instead of a hardcoded
    ``localhost`` map. Only running containers with a host-reachable IP
    appear, so a profile-gated target (e.g. ``workstation``) is present
    exactly when its container is up.
    """
    by_name = _container_index(containers)
    result: dict[str, SSHEndpoint] = {}
    for entry in ENDPOINT_REGISTRY:
        if entry.kind != "ssh":
            continue
        container = by_name.get(entry.container_name)
        if container is None or not _running(container):
            continue
        endpoint = _build_ssh_endpoint(entry, container)
        if endpoint is not None:
            short = entry.container_name.removeprefix(_TERMINAL_CONTAINER_PREFIX)
            result[short] = endpoint
    return result
