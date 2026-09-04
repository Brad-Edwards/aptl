"""Excess-detection, scope, and init-baseline helpers for runtime observation.

These back the fail-closed completeness half of the runtime-concern observers in
:mod:`aptl.backends.raes_runtime_observation` (issue #876 cycle-7 review): a
realized container that carries security-relevant state its contract does not
declare -- an undeclared host-published port, a capability beyond the declared
set, an undeclared bind mount, or a tcp/udp listener the contract omits -- must
fail the concern rather than pass behind an echoed declaration. Only the fixed
state APTL's own generic-substrate init adds (the init capabilities and the
cgroup bind of a systemd node) is subtracted as a known baseline; a plain node
adds nothing.

The scope helpers here also decide when a realized bind address EXACTLY matches
the declared scope, normalizing the wildcard spellings Docker and ``ss`` use.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from raes.runtime_configuration import RuntimeConfiguration

from aptl.runtime_authority import has_undeclared_runtime_mounts

_STATEFUL_MOUNT_KINDS = frozenset({"bind", "tmpfs"})
# Docker reports an all-interfaces bind as an empty HostIp; ``ss`` reports it as
# ``0.0.0.0`` / ``::``. Both are wildcards — broader than any concrete address.
_WILDCARD_ADDRESSES = frozenset({"", "*", "0.0.0.0", "::", "[::]"})

# The ONLY undeclared realized state APTL's own generic substrate contributes,
# fixed and known (issue #876 cycle-7 review). The excess-detection below
# subtracts exactly this baseline before rejecting a concern for undeclared
# state, so a container carrying anything beyond declared-plus-baseline (a
# leftover port from a reused container, a hostile extra listener, an
# undeclared capability or bind mount) is refused rather than silently passed.
#
# Determined empirically against a booted container, not from static reading: a
# plain node adds nothing (no CapAdd, no PortBindings, an empty ``Mounts``); a
# systemd node adds exactly the init capabilities and the cgroup bind (its
# ``--tmpfs`` mounts do not appear in ``Mounts`` at all). ``test_init_baseline_*``
# guards these against drift from the substrate's own init requirements.
_INIT_CAPABILITY_BASELINE = frozenset(
    {"CAP_SYS_ADMIN", "CAP_SYS_NICE", "CAP_SYS_RESOURCE"}
)
_INIT_BIND_MOUNT_TARGETS = frozenset({"/sys/fs/cgroup"})

# The listener half of that same baseline. Docker attaches its embedded DNS
# resolver to every container on a user-defined network, listening on this
# reserved address inside the container's own network namespace, on a tcp and a
# udp port the daemon picks at attach time.
#
# Those two sockets are not workload exposure and cannot be declared: no SDL
# author can name a port Docker chooses per attachment. Counting them as
# undeclared exposure made the excess check reject *every* node that declares a
# service listener, so the SEM-218 realization gate failed the whole lab start
# (issue #951) — the check's own reason for existing (a leftover or hostile
# listener) was never in play. Same carve-out the unix-socket exemption below
# already makes for an init's internal sockets.
_EMBEDDED_DNS_RESOLVER_ADDRESS = "127.0.0.11"


def _sensitivity(value: object) -> str:
    """Return a protocol/sensitivity enum's canonical string value."""

    return str(getattr(value, "value", value) or "")


def _runs_init(runtime: RuntimeConfiguration | None) -> bool:
    """Whether the node runs APTL's systemd init (and so gets the init baseline)."""

    return bool(runtime is not None and runtime.service_manager_units)


def _address_is_wildcard(address: str) -> bool:
    """Return whether an address is an all-interfaces wildcard bind."""

    return address in _WILDCARD_ADDRESSES


def _realized_scope_matches_declared(
    realized_address: str, declared_address: str
) -> bool:
    """Return whether a realized bind address EXACTLY matches the declared scope.

    Both directions are a mismatch, not just one: a concrete declaration realized
    on a wildcard is over-exposed (the original security concern), and a wildcard
    declaration realized on a single interface is under-exposed -- an incomplete
    runtime shape that must not be echoed back as an exact realization (issue #876
    cycle-7 review). Wildcard spellings (empty HostIp from Docker, ``0.0.0.0`` /
    ``::`` from ``ss``) are normalized so they compare equal; every other address
    must match verbatim.
    """

    declared_wild = _address_is_wildcard(declared_address)
    realized_wild = _address_is_wildcard(realized_address)
    if declared_wild or realized_wild:
        return declared_wild and realized_wild
    return realized_address == declared_address


def _port_entry_matches(
    entry: Mapping[str, Any], expected_ip: str, expected_port: str | None
) -> bool:
    """Return whether one realized ``PortBindings`` entry matches the declared scope."""

    realized_ip = entry.get("HostIp") or ""
    realized_port = entry.get("HostPort") or ""
    ip_ok = _realized_scope_matches_declared(realized_ip, expected_ip)
    port_ok = expected_port is None or realized_port == expected_port
    return ip_ok and port_ok


def _normalized_capabilities(values: object) -> set[str]:
    """Return container capabilities in RAES's canonical ``CAP_*`` upper form."""

    normalized: set[str] = set()
    if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
        for value in values:
            if isinstance(value, str) and value.strip():
                name = value.strip().upper().replace("-", "_")
                normalized.add(name if name.startswith("CAP_") else f"CAP_{name}")
    return normalized


def _capabilities_corroborate(
    declared: Mapping[str, Any],
    granted: set[str],
    dropped: set[str],
    baseline: frozenset[str],
) -> bool:
    """Whether realized grants/drops exactly corroborate a declared capability policy.

    A declared drop the container actually grants (present in CapAdd) is not
    dropped at all -- certifying it would let a workload retain a powerful
    capability behind an echoed policy (issue #876 security review). A granted
    capability beyond the declared set plus the known init baseline is undeclared
    privilege (issue #876 cycle-7 review). And every declared add/drop must be
    realized. Any of those makes the policy uncorroborated.
    """

    declared_add = set(declared.get("add") or [])
    declared_drop = set(declared.get("drop") or [])
    if declared_drop & granted:
        return False
    if not granted <= (declared_add | baseline):
        return False
    return declared_add <= granted and declared_drop <= dropped


def _has_undeclared_ports(
    bindings: Mapping[str, Any], declared_ports: tuple[object, ...]
) -> bool:
    """Return whether the container host-publishes a port the contract omits."""

    declared_keys = {
        f"{getattr(port, 'container_port', '')}/{getattr(port, 'protocol', 'tcp')}"
        for port in declared_ports
    }
    for key, entries in bindings.items():
        # An entry present in PortBindings with actual host bindings is a real
        # publication; a key mapped to an empty list is an exposed-but-unpublished
        # port and carries no host reachability.
        if isinstance(entries, Sequence) and entries and key not in declared_keys:
            return True
    return False


def _has_undeclared_mounts(
    realized_mounts: Sequence[object],
    declared: list[object],
    runtime: RuntimeConfiguration,
    *,
    docker_authority_admitted: bool = False,
) -> bool:
    """Return whether the container carries an undeclared bind/tmpfs mount."""

    allowed_targets = {getattr(mount, "target", "") for mount in declared}
    if _runs_init(runtime):
        allowed_targets |= _INIT_BIND_MOUNT_TARGETS
    return has_undeclared_runtime_mounts(
        realized_mounts,
        allowed_targets=allowed_targets,
        docker_authority_admitted=docker_authority_admitted,
    )


def _has_undeclared_network_listeners(
    sockets: tuple[tuple[str, str, int], ...],
    declared: Sequence[object],
) -> bool:
    """Return whether the container serves a tcp/udp listener no declaration covers.

    Docker's own embedded DNS resolver sockets are subtracted first, as runtime
    baseline rather than realized workload state — see
    :func:`_embedded_dns_resolver_sockets`.
    """

    declared_keys = {
        (
            _sensitivity(getattr(listener, "protocol", "")),
            int(getattr(listener, "port")),
        )
        for listener in declared
        if _sensitivity(getattr(listener, "protocol", "")) != "unix"
        and getattr(listener, "port", None) is not None
    }
    baseline = _embedded_dns_resolver_sockets(sockets)
    realized = (socket for socket in sockets if socket not in baseline)
    return any(
        (protocol, port) not in declared_keys for protocol, _address, port in realized
    )


def _embedded_dns_resolver_sockets(
    sockets: tuple[tuple[str, str, int], ...],
) -> frozenset[tuple[str, str, int]]:
    """Return the sockets attributable to Docker's embedded DNS resolver.

    The resolver opens exactly one tcp and one udp socket on
    :data:`_EMBEDDED_DNS_RESOLVER_ADDRESS`. Nothing in the kernel's socket table
    distinguishes those from a workload's own bind, and Linux lets a workload
    bind an unused port on that address too — so exempting the address wholesale
    would let a container hide a backdoor listener behind the baseline.

    Attribution is therefore only safe while the address carries a single socket
    of a protocol. A second one means neither can be attributed, so both stay
    subject to excess detection and the gate rejects: fail closed rather than
    subtract a socket that might be the workload's.
    """

    by_protocol: dict[str, list[tuple[str, str, int]]] = {}
    for socket in sockets:
        protocol, address, _port = socket
        if address == _EMBEDDED_DNS_RESOLVER_ADDRESS:
            by_protocol.setdefault(protocol, []).append(socket)
    return frozenset(
        candidates[0] for candidates in by_protocol.values() if len(candidates) == 1
    )
