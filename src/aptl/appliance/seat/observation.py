"""Authenticated outer-host boundary observation for seat launch."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import rfc8785

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.appliance_boundary_inventory import (
    BoundaryEndpoint,
    HostBoundaryObservation,
)

ListenerProbe = Callable[[], tuple[BoundaryEndpoint, ...]]
HostAddressProbe = Callable[[], tuple[str, ...]]
ConnectProbe = Callable[[str, int, float], bool]


@dataclass(frozen=True)
class HostObservationBundle:
    """Observation plus the digest bound into the launch descriptor."""

    observation: HostBoundaryObservation
    observation_id: str


def observation_id_for(observation: HostBoundaryObservation) -> str:
    """Derive a stable host observation digest independent of completion flags."""

    payload = {
        "policy_digest": observation.policy_digest,
        "payload_digest": observation.payload_digest,
        "boot_id": observation.boot_id,
        "listeners": [item.model_dump(mode="json") for item in observation.listeners],
        "forbidden_reachability_passed": observation.forbidden_reachability_passed,
    }
    digest = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    return f"sha256:{digest}"


def collect_loopback_listeners(
    *,
    probe: ListenerProbe | None = None,
    owner_pid: int | None = None,
) -> tuple[BoundaryEndpoint, ...]:
    """Return loopback listeners, optionally owned by the tracked VM process."""

    if probe is not None:
        return probe()
    return _collect_listeners_via_ss(owner_pid=owner_pid)


def _collect_listeners_via_ss(
    *, owner_pid: int | None = None
) -> tuple[BoundaryEndpoint, ...]:
    """Parse loopback TCP listeners from ``ss`` output when available."""

    try:
        result = subprocess.run(
            ["ss", "-H", "-ltnp"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0:
        return ()
    endpoints: list[BoundaryEndpoint] = []
    for line in result.stdout.splitlines():
        if owner_pid is not None and not any(
            marker in line for marker in (f"pid={owner_pid},", f"pid={owner_pid})")
        ):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if local.startswith("[::1]:"):
            _, port_text = local.split("]:", 1)
            host = "127.0.0.1"
        elif local.startswith("127.0.0.1:"):
            _, port_text = local.split(":", 1)
            host = "127.0.0.1"
        else:
            continue
        try:
            port = int(port_text)
        except ValueError:
            continue
        endpoints.append(
            BoundaryEndpoint(
                audience="participant",
                address=host,
                port=port,
                protocol="tcp",
            )
        )
    return tuple(endpoints)


def _host_nonloopback_addresses() -> tuple[str, ...]:
    """Read bounded global IPv4 addresses from the host network inventory."""

    try:
        result = subprocess.run(
            ["ip", "-j", "address", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
            return ()
        rows = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return ()
    addresses: set[str] = set()
    if not isinstance(rows, list):
        return ()
    for row in rows:
        entries = row.get("addr_info", ()) if isinstance(row, dict) else ()
        for entry in entries if isinstance(entries, list) else ():
            value = entry.get("local") if isinstance(entry, dict) else None
            try:
                parsed = ipaddress.ip_address(value)
            except (TypeError, ValueError):
                continue
            if parsed.version == 4 and not parsed.is_loopback:
                addresses.add(str(parsed))
    return tuple(sorted(addresses))


def _tcp_reachable(address: str, port: int, timeout: float) -> bool:
    """Return whether one forbidden non-loopback TCP endpoint accepts a connect."""

    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_forbidden_host_reachability(
    mappings: tuple[BoundaryEndpoint, ...],
    *,
    address_probe: HostAddressProbe = _host_nonloopback_addresses,
    connect_probe: ConnectProbe = _tcp_reachable,
    timeout_seconds: float = 0.5,
) -> bool:
    """Prove mapped ports do not answer on any observed non-loopback host IPv4."""

    addresses = address_probe()
    tcp_ports = {mapping.port for mapping in mappings if mapping.protocol == "tcp"}
    if not addresses or not tcp_ports:
        return False
    return not any(
        connect_probe(address, port, timeout_seconds)
        for address in addresses
        for port in tcp_ports
    )


def map_publications_to_listeners(
    policy: ApplianceBoundaryPolicy,
    observed: Iterable[BoundaryEndpoint],
    *,
    mappings: tuple[BoundaryEndpoint, ...] = (),
) -> tuple[BoundaryEndpoint, ...]:
    """Attach signed publication audiences to observed loopback listeners."""

    by_port = {(item.address, item.port, item.protocol) for item in observed}
    mapped: list[BoundaryEndpoint] = []
    if mappings:
        allowed = {
            (p.audience, p.address, p.port, p.protocol)
            for p in policy.guest_publications
        }
        if any(
            (m.audience, m.guest_address, m.guest_port, m.protocol) not in allowed
            for m in mappings
        ):
            raise ValueError("outer mapping names an unsigned guest publication")
        return tuple(m for m in mappings if (m.address, m.port, m.protocol) in by_port)
    for publication in policy.guest_publications:
        if publication.audience == "host-mcp":
            raise ValueError("host MCP requires an explicit outer mapping")
        key = (publication.address, publication.port, publication.protocol)
        if key in by_port:
            mapped.append(
                BoundaryEndpoint(
                    audience=publication.audience,
                    address=publication.address,
                    port=publication.port,
                    protocol=publication.protocol,
                )
            )
    return tuple(mapped)


def build_host_observation(
    *,
    binding: ApplianceBoundaryBinding,
    boot_id: str,
    listeners: tuple[BoundaryEndpoint, ...],
    forbidden_reachability_passed: bool,
    complete: bool = True,
) -> HostObservationBundle:
    """Construct one authenticated host observation for the signed binding."""

    observation = HostBoundaryObservation(
        observation_id="pending",
        policy_digest=binding.policy_digest,
        payload_digest=binding.payload_digest,
        boot_id=boot_id,
        complete=complete,
        listeners=listeners,
        forbidden_reachability_passed=forbidden_reachability_passed,
    )
    observation_id = observation_id_for(observation)
    finalized = observation.model_copy(update={"observation_id": observation_id})
    return HostObservationBundle(
        observation=finalized,
        observation_id=observation_id,
    )


def host_boundary_findings(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    host: HostBoundaryObservation,
) -> tuple[str, ...]:
    """Return host-only boundary finding codes."""

    from aptl.core.appliance_boundary_inventory import _append_host_findings

    findings: list[str] = []
    _append_host_findings(policy, binding, host, findings)
    return tuple(findings)
