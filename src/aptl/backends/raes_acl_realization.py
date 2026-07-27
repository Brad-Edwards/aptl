"""Fail-closed RAES infrastructure ACL lowering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from ipaddress import ip_network
from typing import Literal, cast

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends.raes_diagnostics import diagnostic
from aptl.backends.raes_realization_model import NetworkRealization
from aptl.core.deployment.realization import (
    AclAction,
    AclDirection,
    AclProtocol,
    DeploymentAclRealization,
)

_ACTIONS = frozenset({"allow", "deny"})
_DIRECTIONS = frozenset({"in", "out", "inout"})
_PROTOCOLS = frozenset({"any", "tcp", "udp", "icmp"})


def realize_acls(
    resources: Sequence[PlannedResource],
    networks: Sequence[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> list[DeploymentAclRealization]:
    """Lower valid ACLs without creating a second authoring model."""

    network_lookup = {
        ref: network
        for network in networks
        for ref in (network.address, network.name)
        if ref
    }
    network_names = {network.address: network.name for network in networks}
    realized: list[DeploymentAclRealization] = []
    for resource in resources:
        for order, raw in enumerate(_raw_acls(resource)):
            acl = _realize_acl(
                resource,
                raw,
                order,
                network_lookup,
                network_names,
                diagnostics,
            )
            if acl is not None:
                realized.append(acl)
    return realized


def _raw_acls(resource: PlannedResource) -> Sequence[object]:
    """Return an ACL sequence only from the canonical infrastructure field."""

    payload = resource.payload
    result: Sequence[object] = ()
    if isinstance(payload, Mapping):
        spec = payload.get("spec")
        if isinstance(spec, Mapping):
            infrastructure = spec.get("infrastructure")
            if isinstance(infrastructure, Mapping):
                raw = infrastructure.get("acls", ())
                if isinstance(raw, list | tuple):
                    result = raw
    return result


def _realize_acl(
    resource: PlannedResource,
    raw: object,
    order: int,
    network_lookup: Mapping[str, NetworkRealization],
    network_names: Mapping[str, str],
    diagnostics: list[Diagnostic],
) -> DeploymentAclRealization | None:
    """Validate and lower one admitted ACL rule."""

    if not isinstance(raw, Mapping):
        diagnostics.append(
            _acl_diagnostic(resource, "shape-invalid", "ACL entry is not a mapping.")
        )
        return None
    before = len(diagnostics)
    action = _token(raw, "action")
    direction = _token(raw, "direction") or "inout"
    protocol = _token(raw, "protocol") or "any"
    from_network = _token(raw, "from_net")
    to_network = _token(raw, "to_net")
    ports = _ports(resource, raw.get("ports", ()), protocol, diagnostics)
    _validate_token(resource, "action", action, _ACTIONS, diagnostics)
    _validate_token(resource, "direction", direction, _DIRECTIONS, diagnostics)
    _validate_token(resource, "protocol", protocol, _PROTOCOLS, diagnostics)
    _validate_endpoint(resource, from_network, network_lookup, diagnostics)
    _validate_endpoint(resource, to_network, network_lookup, diagnostics)
    if len(diagnostics) != before:
        return None
    return DeploymentAclRealization(
        owner_address=resource.address,
        owner_resource_type=cast(Literal["node", "network"], resource.resource_type),
        owner_name=(
            network_names.get(resource.address, "")
            if resource.resource_type == "network"
            else _payload_name(resource)
        ),
        name=_token(raw, "name") or f"acl-{order}",
        order=order,
        direction=cast(AclDirection, direction),
        from_network=from_network or None,
        to_network=to_network or None,
        protocol=cast(AclProtocol, protocol),
        ports=ports,
        action=cast(AclAction, action),
    )


def _token(raw: Mapping[object, object], key: str) -> str:
    """Normalize a string token without coercing other input types."""

    value = raw.get(key)
    return value.strip().lower() if isinstance(value, str) else ""


def _payload_name(resource: PlannedResource) -> str:
    """Read a node name from the admitted resource payload."""

    payload = resource.payload
    name = payload.get("name") if isinstance(payload, Mapping) else None
    return name if isinstance(name, str) else ""


def _validate_token(
    resource: PlannedResource,
    field: str,
    value: str,
    allowed: frozenset[str],
    diagnostics: list[Diagnostic],
) -> None:
    """Record a stable diagnostic for an unsupported ACL token."""

    if value not in allowed:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                f"{field}-unsupported",
                f"RAES ACL {field} is unsupported by this backend.",
            )
        )


def _validate_endpoint(
    resource: PlannedResource,
    value: str,
    network_lookup: Mapping[str, NetworkRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Require an ACL endpoint to resolve to an admitted IPv4 network."""

    if not value:
        return
    if value not in network_lookup:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                "endpoint-unresolved",
                "RAES ACL endpoint does not resolve to an admitted network.",
            )
        )
        return
    cidr = network_lookup[value].cidr
    try:
        supported = bool(cidr) and ip_network(cidr, strict=False).version == 4
    except ValueError:
        supported = False
    if not supported:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                "endpoint-family-unsupported",
                "RAES ACL endpoint requires an observed IPv4 network.",
            )
        )


def _ports(
    resource: PlannedResource,
    raw: object,
    protocol: str,
    diagnostics: list[Diagnostic],
) -> tuple[int, ...]:
    """Validate transport ports and return an immutable ordered sequence."""

    result: tuple[int, ...] = ()
    if not isinstance(raw, list | tuple) or any(
        not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535
        for port in raw
    ):
        diagnostics.append(
            _acl_diagnostic(resource, "ports-invalid", "RAES ACL ports are invalid.")
        )
    elif raw and protocol in _PROTOCOLS and protocol not in {"tcp", "udp"}:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                "ports-protocol-unsupported",
                "RAES ACL ports require TCP or UDP.",
            )
        )
    else:
        result = tuple(cast(int, port) for port in raw)
    return result


def _acl_diagnostic(
    resource: PlannedResource,
    suffix: str,
    message: str,
) -> Diagnostic:
    """Build one resource-scoped ACL admission diagnostic."""

    return diagnostic(
        f"aptl.provisioner.acl-{suffix}",
        resource.address,
        message,
    )
