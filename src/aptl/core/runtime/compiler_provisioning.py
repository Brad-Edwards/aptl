"""Provisioning-domain builders for the SDL-to-runtime compiler.

Builds the network/node deployments, feature bindings, and content and account
placements that make up the provisioning portion of the runtime model.
"""

from aptl.core.runtime.compiler_addresses import (
    _account_address,
    _content_address,
    _dedupe,
    _dump,
    _feature_binding_address,
    _network_address,
    _node_address,
    _resource_address_for_node,
)
from aptl.core.runtime.compiler_resolvers import NodeRefContext, _resolve_node_ref
from aptl.core.runtime.models import (
    AccountPlacement,
    ContentPlacement,
    Diagnostic,
    FeatureBinding,
    NetworkRuntime,
    NodeRuntime,
    RuntimeTemplate,
)
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario


def _resolve_infrastructure_deps(
    scenario: Scenario,
    *,
    node_name: str,
    dep_names: list[str],
    code_prefix: str,
    node_label: str,
    require_switch: bool = False,
) -> tuple[list[str], list[Diagnostic]]:
    """Resolve a node's infrastructure dependency or link references."""
    addresses: list[str] = []
    diagnostics: list[Diagnostic] = []
    owner_address = _resource_address_for_node(scenario, node_name)
    for dep_name in dep_names:
        dep_address, dep_diagnostics = _resolve_node_ref(
            scenario,
            NodeRefContext(
                owner_address=owner_address,
                domain="provisioning",
                code_prefix=code_prefix,
                node_label=node_label,
                require_switch=require_switch,
            ),
            ref_name=dep_name,
        )
        diagnostics.extend(dep_diagnostics)
        if dep_address is not None:
            addresses.append(dep_address)
    return addresses, diagnostics


def _build_node_deployments(
    scenario: Scenario,
) -> tuple[dict[str, NetworkRuntime], dict[str, NodeRuntime], list[Diagnostic]]:
    """Build network and node deployment resources from scenario nodes."""
    networks: dict[str, NetworkRuntime] = {}
    node_deployments: dict[str, NodeRuntime] = {}
    diagnostics: list[Diagnostic] = []

    for node_name, node in scenario.nodes.items():
        node_spec = _dump(node)
        infra = scenario.infrastructure.get(node_name)
        infra_spec = _dump(infra) if infra is not None else {}
        ordering_deps: list[str] = []
        refresh_deps: list[str] = []
        if infra is not None:
            dep_addresses, dep_diagnostics = _resolve_infrastructure_deps(
                scenario,
                node_name=node_name,
                dep_names=list(infra.dependencies),
                code_prefix="provisioning.infrastructure-dependency-ref",
                node_label="infrastructure dependency",
            )
            diagnostics.extend(dep_diagnostics)
            ordering_deps.extend(dep_addresses)
            refresh_deps.extend(dep_addresses)
            link_addresses, link_diagnostics = _resolve_infrastructure_deps(
                scenario,
                node_name=node_name,
                dep_names=list(infra.links),
                code_prefix="provisioning.infrastructure-link-ref",
                node_label="infrastructure link",
                require_switch=True,
            )
            diagnostics.extend(link_diagnostics)
            ordering_deps.extend(link_addresses)
            refresh_deps.extend(link_addresses)
        spec = {
            "node": node_spec,
            "infrastructure": infra_spec,
        }

        if node.type == NodeType.SWITCH:
            networks[_network_address(node_name)] = NetworkRuntime(
                address=_network_address(node_name),
                name=node_name,
                node_name=node_name,
                spec=spec,
                ordering_dependencies=_dedupe(ordering_deps),
                refresh_dependencies=_dedupe(refresh_deps),
            )
        else:
            node_deployments[_node_address(node_name)] = NodeRuntime(
                address=_node_address(node_name),
                name=node_name,
                node_name=node_name,
                node_type=node_spec.get("type", ""),
                os_family=node_spec.get("os", "") or "",
                count=infra_spec.get("count"),
                spec=spec,
                ordering_dependencies=_dedupe(ordering_deps),
                refresh_dependencies=_dedupe(refresh_deps),
            )

    return networks, node_deployments, diagnostics


def _feature_dependency_addresses(
    node_name: str,
    node_addr: str,
    *,
    feature_dependencies: list[str],
    node_features: dict[str, str],
) -> list[str]:
    """Collect the binding dependency addresses for one feature binding."""
    dep_addresses = [node_addr]
    for dep_name in feature_dependencies:
        if dep_name in node_features:
            dep_addresses.append(_feature_binding_address(node_name, dep_name))
    return dep_addresses


def _build_feature_bindings(
    scenario: Scenario,
    feature_templates: dict[str, RuntimeTemplate],
) -> tuple[dict[str, FeatureBinding], list[Diagnostic]]:
    """Bind declared node features to their feature templates."""
    feature_bindings: dict[str, FeatureBinding] = {}
    diagnostics: list[Diagnostic] = []
    for node_name, node in scenario.nodes.items():
        if node.type != NodeType.VM:
            continue
        node_addr = _node_address(node_name)
        for feature_name, role_name in node.features.items():
            template = feature_templates.get(feature_name)
            feature = scenario.features.get(feature_name)
            if template is None or feature is None:
                diagnostics.append(
                    Diagnostic(
                        code="provisioning.feature-template-ref-unbound",
                        domain="provisioning",
                        address=node_addr,
                        message=(
                            f"Feature binding '{feature_name}' on node '{node_name}' "
                            "does not resolve to a declared feature template."
                        ),
                    )
                )
                continue
            dep_addresses = _feature_dependency_addresses(
                node_name,
                node_addr,
                feature_dependencies=list(feature.dependencies),
                node_features=node.features,
            )
            address = _feature_binding_address(node_name, feature_name)
            feature_bindings[address] = FeatureBinding(
                address=address,
                name=feature_name,
                node_name=node_name,
                node_address=node_addr,
                feature_name=feature_name,
                template_address=template.address,
                role_name=role_name,
                ordering_dependencies=_dedupe(dep_addresses),
                refresh_dependencies=_dedupe(dep_addresses),
                spec={
                    "binding": {
                        "node": node_name,
                        "role": role_name,
                    },
                    "template": template.spec,
                },
            )
    return feature_bindings, diagnostics


def _build_content_placements(
    scenario: Scenario,
) -> tuple[dict[str, ContentPlacement], list[Diagnostic]]:
    """Place declared content onto its target VM nodes."""
    content_placements: dict[str, ContentPlacement] = {}
    diagnostics: list[Diagnostic] = []
    for name, content in scenario.content.items():
        address = _content_address(name)
        target_address, target_diagnostics = _resolve_node_ref(
            scenario,
            NodeRefContext(
                owner_address=address,
                domain="provisioning",
                code_prefix="provisioning.content-target-ref",
                node_label="content target",
                require_vm=True,
            ),
            ref_name=content.target,
        )
        diagnostics.extend(target_diagnostics)
        if target_address is None:
            continue
        content_placements[address] = ContentPlacement(
            address=address,
            name=name,
            content_name=name,
            target_node=content.target,
            target_address=target_address,
            ordering_dependencies=(target_address,),
            refresh_dependencies=(target_address,),
            spec=_dump(content),
        )
    return content_placements, diagnostics


def _build_account_placements(
    scenario: Scenario,
) -> tuple[dict[str, AccountPlacement], list[Diagnostic]]:
    """Place declared accounts onto their target VM nodes."""
    account_placements: dict[str, AccountPlacement] = {}
    diagnostics: list[Diagnostic] = []
    for name, account in scenario.accounts.items():
        address = _account_address(name)
        target_address, target_diagnostics = _resolve_node_ref(
            scenario,
            NodeRefContext(
                owner_address=address,
                domain="provisioning",
                code_prefix="provisioning.account-node-ref",
                node_label="account node",
                require_vm=True,
            ),
            ref_name=account.node,
        )
        diagnostics.extend(target_diagnostics)
        if target_address is None:
            continue
        account_placements[address] = AccountPlacement(
            address=address,
            name=name,
            account_name=name,
            node_name=account.node,
            target_address=target_address,
            ordering_dependencies=(target_address,),
            refresh_dependencies=(target_address,),
            spec=_dump(account),
        )
    return account_placements, diagnostics
