"""Network topology validation for ACES-to-APTL realization."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

from aces_contracts.diagnostics import Diagnostic

from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_profiles import normalize_identifier
from aptl.backends.aces_realization_model import NetworkRealization, NodeRealization


def append_network_topology_diagnostics(
    nodes: list[NodeRealization],
    networks: list[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Validate provider-relevant network topology before backend side effects."""

    parsed_networks = _parsed_networks(networks, diagnostics)
    _append_network_name_diagnostics(networks, diagnostics)
    seen_addresses: dict[tuple[str, str], str] = {}
    for node in nodes:
        _append_node_static_address_diagnostics(
            node,
            parsed_networks,
            seen_addresses,
            diagnostics,
        )


def _append_node_static_address_diagnostics(
    node: NodeRealization,
    parsed_networks: dict[str, IPv4Network],
    seen_addresses: dict[tuple[str, str], str],
    diagnostics: list[Diagnostic],
) -> None:
    """Validate static addresses declared for one realized node."""

    linked_networks = set(node.networks)
    for network_name, raw_address in node.static_address_assignments:
        if network_name not in linked_networks:
            _append_unlinked_static_address_diagnostic(node, diagnostics)
        parsed_address = _parsed_static_address(node.address, raw_address, diagnostics)
        if parsed_address is not None:
            _append_static_address_policy_diagnostics(
                node,
                network_name,
                parsed_address,
                parsed_networks,
                seen_addresses,
                diagnostics,
            )


def _append_static_address_policy_diagnostics(
    node: NodeRealization,
    network_name: str,
    parsed_address: IPv4Address,
    parsed_networks: dict[str, IPv4Network],
    seen_addresses: dict[tuple[str, str], str],
    diagnostics: list[Diagnostic],
) -> None:
    """Validate one parsed static address against network and peer state."""

    network_key = _network_identity_key(network_name)
    parsed_network = parsed_networks.get(network_key)
    if parsed_network is not None and parsed_address not in parsed_network:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-static-address-out-of-range",
                node.address,
                "ACES node static address is outside the declared network CIDR.",
            )
        )
    _append_duplicate_static_address_diagnostic(
        node,
        network_key,
        parsed_address,
        seen_addresses,
        diagnostics,
    )


def _append_unlinked_static_address_diagnostic(
    node: NodeRealization,
    diagnostics: list[Diagnostic],
) -> None:
    """Report a static address that targets a network the node did not link."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.network-static-address-unlinked",
            node.address,
            (
                "ACES node static address references a network "
                "that is not declared in the node links."
            ),
        )
    )


def _append_duplicate_static_address_diagnostic(
    node: NodeRealization,
    network_key: str,
    parsed_address: IPv4Address,
    seen_addresses: dict[tuple[str, str], str],
    diagnostics: list[Diagnostic],
) -> None:
    """Report duplicate per-network static addresses."""

    owner_key = (network_key, str(parsed_address))
    prior_owner = seen_addresses.get(owner_key)
    if prior_owner is not None and prior_owner != node.address:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-static-address-duplicate",
                node.address,
                "ACES node static address duplicates another node.",
            )
        )
    else:
        seen_addresses[owner_key] = node.address


def _parsed_networks(
    networks: list[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> dict[str, IPv4Network]:
    """Return parsed network CIDRs keyed by backend identity stem."""

    parsed: dict[str, IPv4Network] = {}
    for network in networks:
        key = _network_identity_key(network.name)
        parsed_network = _parsed_cidr(network, diagnostics)
        if parsed_network is not None:
            parsed[key] = parsed_network
        _append_gateway_diagnostics(network, parsed_network, diagnostics)
    return parsed


def _parsed_cidr(
    network: NetworkRealization,
    diagnostics: list[Diagnostic],
) -> IPv4Network | None:
    """Parse a network CIDR and append a diagnostic on invalid input."""

    parsed: IPv4Network | None = None
    if network.cidr is not None:
        try:
            parsed_value = ip_network(network.cidr, strict=True)
        except ValueError:
            _append_invalid_cidr_diagnostic(network, diagnostics)
        else:
            if isinstance(parsed_value, IPv4Network):
                parsed = parsed_value
            else:
                _append_invalid_cidr_diagnostic(network, diagnostics)
    return parsed


def _append_invalid_cidr_diagnostic(
    network: NetworkRealization,
    diagnostics: list[Diagnostic],
) -> None:
    """Report a network CIDR that is not a valid IPv4 network."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.network-cidr-invalid",
            network.address,
            "ACES network CIDR is not a valid IPv4 network.",
        )
    )


def _append_gateway_diagnostics(
    network: NetworkRealization,
    parsed_network: IPv4Network | None,
    diagnostics: list[Diagnostic],
) -> None:
    """Validate a network gateway, if one was authored."""

    if network.gateway is None:
        return
    try:
        parsed_gateway = ip_address(network.gateway)
    except ValueError:
        _append_invalid_gateway_diagnostic(network, diagnostics)
        return
    if not isinstance(parsed_gateway, IPv4Address):
        _append_invalid_gateway_diagnostic(network, diagnostics)
        return
    if parsed_network is not None and parsed_gateway not in parsed_network:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-gateway-out-of-range",
                network.address,
                "ACES network gateway is outside the declared CIDR.",
            )
        )


def _append_invalid_gateway_diagnostic(
    network: NetworkRealization,
    diagnostics: list[Diagnostic],
) -> None:
    """Report a network gateway that is not a valid IPv4 address."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.network-gateway-invalid",
            network.address,
            "ACES network gateway is not a valid IPv4 address.",
        )
    )


def _parsed_static_address(
    node_address: str,
    raw_address: str,
    diagnostics: list[Diagnostic],
) -> IPv4Address | None:
    """Parse a node static address and append a diagnostic on invalid input."""

    parsed: IPv4Address | None = None
    try:
        parsed_value = ip_address(raw_address)
    except ValueError:
        _append_invalid_static_address_diagnostic(node_address, diagnostics)
    else:
        if isinstance(parsed_value, IPv4Address):
            parsed = parsed_value
        else:
            _append_invalid_static_address_diagnostic(node_address, diagnostics)
    return parsed


def _append_invalid_static_address_diagnostic(
    node_address: str,
    diagnostics: list[Diagnostic],
) -> None:
    """Report a node static address that is not a valid IPv4 address."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.network-static-address-invalid",
            node_address,
            "ACES node static address is not a valid IPv4 address.",
        )
    )


def _append_network_name_diagnostics(
    networks: list[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Report networks that normalize to the same backend identity stem."""

    index: dict[str, NetworkRealization] = {}
    for network in networks:
        key = _network_identity_key(network.name)
        prior = index.get(key)
        if prior is not None and prior.address != network.address:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.network-name-ambiguous",
                    network.address,
                    "ACES network names normalize to the same backend network.",
                )
            )
        else:
            index[key] = network


def _network_identity_key(name: str) -> str:
    """Return the project-scoped backend network identity stem."""

    normalized = normalize_identifier(name)
    if normalized.endswith("-net"):
        normalized = normalized.removesuffix("-net")
    if normalized.startswith("aptl-"):
        normalized = normalized.removeprefix("aptl-")
    return normalized
