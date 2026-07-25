"""Fail-closed ACES infrastructure ACL lowering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from ipaddress import ip_network
from typing import Literal, cast

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_realization_model import NetworkRealization
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
    payload = resource.payload
    if not isinstance(payload, Mapping):
        return ()
    spec = payload.get("spec")
    if not isinstance(spec, Mapping):
        return ()
    infrastructure = spec.get("infrastructure")
    if not isinstance(infrastructure, Mapping):
        return ()
    raw = infrastructure.get("acls", ())
    return raw if isinstance(raw, list | tuple) else ()


def _realize_acl(
    resource: PlannedResource,
    raw: object,
    order: int,
    network_lookup: Mapping[str, NetworkRealization],
    network_names: Mapping[str, str],
    diagnostics: list[Diagnostic],
) -> DeploymentAclRealization | None:
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
        owner_resource_type=cast(
            Literal["node", "network"], resource.resource_type
        ),
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
    value = raw.get(key)
    return value.strip().lower() if isinstance(value, str) else ""


def _payload_name(resource: PlannedResource) -> str:
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
    if value not in allowed:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                f"{field}-unsupported",
                f"ACES ACL {field} is unsupported by this backend.",
            )
        )


def _validate_endpoint(
    resource: PlannedResource,
    value: str,
    network_lookup: Mapping[str, NetworkRealization],
    diagnostics: list[Diagnostic],
) -> None:
    if not value:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                "endpoint-wildcard-unsupported",
                "ACES ACL wildcard endpoints are unsupported by this backend.",
            )
        )
    elif value not in network_lookup:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                "endpoint-unresolved",
                "ACES ACL endpoint does not resolve to an admitted network.",
            )
        )
    else:
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
                    "ACES ACL endpoint requires an observed IPv4 network.",
                )
            )


def _ports(
    resource: PlannedResource,
    raw: object,
    protocol: str,
    diagnostics: list[Diagnostic],
) -> tuple[int, ...]:
    if not isinstance(raw, list | tuple):
        diagnostics.append(
            _acl_diagnostic(resource, "ports-invalid", "ACES ACL ports are invalid.")
        )
        return ()
    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 0 < port <= 65535
        for port in raw
    ):
        diagnostics.append(
            _acl_diagnostic(resource, "ports-invalid", "ACES ACL ports are invalid.")
        )
        return ()
    if raw and protocol in _PROTOCOLS and protocol not in {"tcp", "udp"}:
        diagnostics.append(
            _acl_diagnostic(
                resource,
                "ports-protocol-unsupported",
                "ACES ACL ports require TCP or UDP.",
            )
        )
        return ()
    return tuple(cast(int, port) for port in raw)


def _acl_diagnostic(
    resource: PlannedResource,
    suffix: str,
    message: str,
) -> Diagnostic:
    return diagnostic(
        f"aptl.provisioner.acl-{suffix}",
        resource.address,
        message,
    )
