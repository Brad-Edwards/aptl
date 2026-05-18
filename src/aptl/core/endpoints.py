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
- ``RangeSnapshot.to_dict()`` remains the redaction boundary; the
  ``credentials`` field carries the existing display strings unchanged
  for one-place deduplication only, not as a credential-management
  layer.
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
class EndpointRegistryEntry:
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
    ``credentials`` is optional and only carries the existing snapshot
    display strings used today by ``aptl lab status``; it must not be
    repurposed as a credential-management surface (ADR-029).
    """

    container_name: str
    display_name: str
    kind: EndpointKind
    target_port: int
    url_scheme: str | None = None
    transport_protocol: str = "tcp"
    ssh_user: str | None = None
    credentials: str | None = None


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
        credentials="admin/SecretPassword",
    ),
    EndpointRegistryEntry(
        container_name="aptl-wazuh-indexer",
        display_name="Wazuh Indexer",
        kind="service",
        target_port=9200,
        url_scheme="https",
        transport_protocol="tcp",
        credentials="admin/SecretPassword",
    ),
    EndpointRegistryEntry(
        container_name="aptl-wazuh-manager",
        display_name="Wazuh API",
        kind="service",
        target_port=55000,
        url_scheme="https",
        transport_protocol="tcp",
        credentials="wazuh-wui/WazuhPass123!",
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
)


def _parse_port_entry(entry: str) -> tuple[int, int, str] | None:
    """Parse one ``docker ps``-style port mapping string.

    Returns ``(host_port, target_port, protocol)`` for a published
    mapping (``<host_ip>:<host_port>-><target>/<proto>``), or ``None``
    for exposed-but-not-published (``22/tcp``), malformed entries, or
    anything we cannot confidently parse. Intentionally narrow — this
    is not a general Compose parser (ADR-036 anti-pattern guard).
    """
    if "->" not in entry:
        return None
    left, right = entry.split("->", 1)
    # left is "<host_ip>:<host_port>"; right is "<target>/<proto>".
    if ":" not in left or "/" not in right:
        return None
    host_port_str = left.rsplit(":", 1)[1]
    target_port_str, protocol = right.split("/", 1)
    if not host_port_str.isdigit() or not target_port_str.isdigit():
        return None
    return int(host_port_str), int(target_port_str), protocol.strip()


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


def _running(container: ContainerSnapshot) -> bool:
    return "Up" in container.status


def _container_index(
    containers: list[ContainerSnapshot],
) -> dict[str, ContainerSnapshot]:
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
        if entry.url_scheme is None:  # pragma: no cover - registry invariant
            continue
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
                credentials=entry.credentials or "",
            )
        )
    return endpoints


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
        if entry.ssh_user is None:  # pragma: no cover - registry invariant
            continue
        host_port = parse_host_port(
            container.ports,
            entry.target_port,
            protocol=entry.transport_protocol,
        )
        if host_port is None:
            continue
        command = (
            f"ssh -i {_SSH_KEY_PATH} {entry.ssh_user}@localhost -p {host_port}"
        )
        endpoints.append(
            SSHEndpoint(
                name=entry.display_name,
                host="localhost",
                port=host_port,
                user=entry.ssh_user,
                key_path=_SSH_KEY_PATH,
                command=command,
            )
        )
    return endpoints
