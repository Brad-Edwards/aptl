"""Host port publishing: conflict detection, remap, and reporting.

Docker Compose aborts an entire ``up`` if it cannot bind a requested host
port, and on Windows/macOS other software routinely holds ports the lab wants
— mDNS on UDP 5353, an editor's automatic port-forwarding, another service on
3100, and so on. On Windows a held IPv6 ``::1:PORT`` even blocks Docker's IPv4
``127.0.0.1:PORT`` publish, so the clash is easy to hit and fails the whole
start.

To keep ``aptl lab start`` robust, the published host ports in
``docker-compose.yml`` are written through a ``${VAR:-default}`` indirection.
Before Compose runs, :func:`resolve_host_ports` parses those ports, probes each
one, and for any that are already in use picks a free port and exports the
override through the process environment (which Compose reads for variable
substitution on every code path, with no change to how the compose command is
built). The resolved mapping is returned so the CLI can report the real URL of
every service — no matter what it was remapped to.

Nothing here changes lab internals: containers reach each other over the
Docker networks, never the host publishes. Remapping only affects how the
operator's host reaches a service's web UI / SSH.
"""

from __future__ import annotations

import errno
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path

import yaml

from aptl.utils.logging import get_logger

log = get_logger("host_ports")

_COMPOSE_FILENAME = "docker-compose.yml"

# A published-port short-syntax entry: ``[ip:]host:container[/proto]`` where the
# host part may be a literal number or a ``${VAR:-default}`` reference.
_PORT_ENTRY = re.compile(
    r"^(?:(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\[[^\]]+\]):)?"
    r"(?P<host>\$\{[^}]+\}|\d+):"
    r"(?P<container>\d+)"
    r"(?:/(?P<proto>\w+))?$"
)
_VAR_REF = re.compile(r"^\$\{(?P<var>[A-Za-z_]\w*)(?::-(?P<default>\d+))?\}$", re.ASCII)

# Where to start scanning for a replacement port when a default is taken. Kept
# above the ephemeral/registered ranges the lab itself uses so a remap does not
# land on another lab default.
_REMAP_SCAN_START = 20000
_REMAP_SCAN_END = 60000


@dataclass(frozen=True)
class PortSpec:
    """One published host port parsed from the compose file."""

    service: str
    env_var: str | None
    default_port: int
    container_port: int
    proto: str
    # None => all interfaces
    host_ip: str | None


@dataclass(frozen=True)
class ResolvedPort:
    """A published host port after conflict resolution."""

    service: str
    env_var: str | None
    default_port: int
    resolved_port: int
    protos: tuple[str, ...]
    host_ip: str | None
    remapped: bool


def _proto_socktype(proto: str) -> int:
    """Return the socket type used to probe a published-port protocol."""
    return socket.SOCK_DGRAM if proto.lower() == "udp" else socket.SOCK_STREAM


def port_available(port: int, proto: str, host_ip: str | None) -> bool:
    """Return True if *port* looks free to publish for *proto*.

    Probes both IPv4 and IPv6 loopback (and the wildcard when the publish has
    no host-IP) because on Windows a process holding ``::1:PORT`` blocks
    Docker's ``127.0.0.1:PORT`` publish; an *address-in-use* failure on either
    family is the same conflict Docker would hit.

    Only ``EADDRINUSE`` counts as occupied. A privileged-port ``EACCES`` (ports
    below 1024 on Linux/macOS cannot be bound by an unprivileged probe, but the
    Docker daemon binds them as root) must NOT be read as a conflict — otherwise
    the probe would falsely remap 443/514/etc. and change the published ports on
    Linux/macOS. Any other bind error is likewise treated as "leave it alone".
    """
    socktype = _proto_socktype(proto)
    targets: list[tuple[int, str]] = []
    if host_ip and ":" not in host_ip:
        targets.append((socket.AF_INET, host_ip))
    else:
        # Loopback-only publish is probed on both stacks; an all-interfaces
        # publish (no host_ip) is probed on the wildcards.
        if host_ip is None:
            targets.append((socket.AF_INET, "0.0.0.0"))
            targets.append((socket.AF_INET6, "::"))
        targets.append((socket.AF_INET, "127.0.0.1"))
        targets.append((socket.AF_INET6, "::1"))

    for family, addr in targets:
        sock = socket.socket(family, socktype)
        try:
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((addr, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return False
            # EACCES (privileged port) or any other error: not a demonstrable
            # conflict — do not remap.
            continue
        finally:
            sock.close()
    return True


def _group_available(port: int, protos: tuple[str, ...], host_ip: str | None) -> bool:
    """Return True when *port* is available for every protocol in a group."""
    return all(port_available(port, proto, host_ip) for proto in protos)


def _find_free_port(
    protos: tuple[str, ...], host_ip: str | None, avoid: set[int]
) -> int | None:
    """Find a port free for every protocol in the group, skipping *avoid*."""
    for candidate in range(_REMAP_SCAN_START, _REMAP_SCAN_END):
        if candidate in avoid:
            continue
        if _group_available(candidate, protos, host_ip):
            return candidate
    return None


def _parse_host_port_ref(host: str) -> tuple[str | None, int] | None:
    """Parse a host-port token into ``(env_var, default_port)``."""
    var_match = _VAR_REF.match(host)
    if var_match is None:
        return None, int(host)
    default_raw = var_match.group("default")
    if default_raw is None:
        return None
    return var_match.group("var"), int(default_raw)


def _parse_entry(service: str, entry: object) -> PortSpec | None:
    """Parse one compose ``ports`` entry into a :class:`PortSpec`.

    Only short-string syntax is handled (what this compose file uses). Long
    dict-form entries and anything unparseable are skipped — they simply are
    not eligible for automatic remapping.
    """
    match = _PORT_ENTRY.match(entry.strip()) if isinstance(entry, str) else None
    if match is None:
        return None
    parsed_host = _parse_host_port_ref(match.group("host"))
    if parsed_host is None:
        # ${VAR} with no default: leave to the operator.
        return None
    env_var, default_port = parsed_host
    return PortSpec(
        service=service,
        env_var=env_var,
        default_port=default_port,
        container_port=int(match.group("container")),
        proto=(match.group("proto") or "tcp").lower(),
        host_ip=match.group("ip"),
    )


def parse_published_ports(compose: dict[str, object]) -> list[PortSpec]:
    """Return every published host port declared in a compose mapping."""
    specs: list[PortSpec] = []
    for service, cfg in (compose.get("services") or {}).items():
        if not isinstance(cfg, dict):
            continue
        for entry in cfg.get("ports") or []:
            spec = _parse_entry(service, entry)
            if spec is not None:
                specs.append(spec)
    return specs


def _load_compose(project_dir: Path) -> dict[str, object] | None:
    """Load the project compose file if it exists and is a mapping."""
    compose_path = project_dir / _COMPOSE_FILENAME
    if not compose_path.exists():
        return None
    try:
        loaded = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        log.warning("Could not parse %s for port resolution: %s", compose_path, exc)
        return None
    return loaded if isinstance(loaded, dict) else None


def _resolved_for_pinned(
    first: PortSpec,
    env_var: str,
    default_port: int,
    protos: tuple[str, ...],
) -> ResolvedPort:
    """Return the operator-selected mapping for an explicitly pinned env var."""
    pinned = os.environ.get(env_var)
    resolved_port = int(pinned) if pinned and pinned.isdigit() else default_port
    return ResolvedPort(
        service=first.service,
        env_var=env_var,
        default_port=default_port,
        resolved_port=resolved_port,
        protos=protos,
        host_ip=first.host_ip,
        remapped=False,
    )


def _resolve_group(
    env_var: str,
    specs: list[PortSpec],
    reserved: set[str],
    taken: set[int],
) -> ResolvedPort:
    """Resolve one env-var port group and update environment overrides."""
    first = specs[0]
    protos = tuple(sorted({s.proto for s in specs}))
    default_port = first.default_port
    if env_var in reserved or env_var in os.environ:
        return _resolved_for_pinned(first, env_var, default_port, protos)

    if _group_available(default_port, protos, first.host_ip):
        return _resolved(first, env_var, default_port, default_port, protos)

    free = _find_free_port(protos, first.host_ip, taken)
    if free is None:
        log.warning(
            "No free host port found to remap %s (default %d); leaving default.",
            first.service,
            default_port,
        )
        return _resolved(first, env_var, default_port, default_port, protos)

    taken.add(free)
    os.environ[env_var] = str(free)
    log.info(
        "Host port %d for %s is in use; publishing on %d instead (%s).",
        default_port,
        first.service,
        free,
        env_var,
    )
    return _resolved(first, env_var, default_port, free, protos)


def resolve_host_ports(
    project_dir: Path, reserved_env: set[str] | None = None
) -> list[ResolvedPort]:
    """Detect occupied published host ports, remap them, and export overrides.

    For each ``${VAR:-default}`` published port, probe the default; if it is
    already in use, choose a free port and set ``os.environ[VAR]`` so Compose
    publishes there instead. Ports the operator pinned explicitly (present in
    *reserved_env* or already in ``os.environ``) are honoured as-is. Returns
    the resolved mapping for every parameterized port so callers can report the
    real host port of each service.
    """
    reserved = set(reserved_env or set())
    compose = _load_compose(project_dir)
    if compose is None:
        return []

    # Group entries that share an env var (e.g. DNS tcp+udp on one host port)
    # so they move together and land on a port free for every protocol.
    groups: dict[str, list[PortSpec]] = {}
    for spec in parse_published_ports(compose):
        if spec.env_var is None:
            continue
        groups.setdefault(spec.env_var, []).append(spec)

    resolved: list[ResolvedPort] = []
    taken: set[int] = {s.default_port for specs in groups.values() for s in specs}
    for env_var, specs in sorted(groups.items()):
        resolved.append(_resolve_group(env_var, specs, reserved, taken))

    return resolved


def _resolved(
    spec: PortSpec,
    env_var: str,
    default_port: int,
    resolved_port: int,
    protos: tuple[str, ...],
) -> ResolvedPort:
    """Build a resolved-port record from a compose port spec."""
    return ResolvedPort(
        service=spec.service,
        env_var=env_var,
        default_port=default_port,
        resolved_port=resolved_port,
        protos=protos,
        host_ip=spec.host_ip,
        remapped=resolved_port != default_port,
    )
