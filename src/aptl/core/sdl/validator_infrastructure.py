"""Validation passes for nodes, infrastructure, content and accounts.

These passes enforce cross-reference integrity for the deployment topology:
node feature/condition/inject/vulnerability references, infrastructure links
and ACLs, IP-within-CIDR consistency, and node-targeting for content and
accounts.
"""

from collections.abc import Mapping
from ipaddress import ip_address, ip_network

from aptl.core.sdl.infrastructure import InfraNode, SimpleProperties
from aptl.core.sdl.nodes import MAX_NODE_NAME_LENGTH, Node, NodeType
from aptl.core.sdl.validator_base import _ValidatorCore


class _InfrastructureMixin(_ValidatorCore):
    """Node, infrastructure, content and account validation passes."""

    def _verify_node_role_refs(
        self,
        name: str,
        node: Node,
        section_label: str,
        ref_roles: dict[str, str],
        defined: Mapping[str, object],
    ) -> None:
        """Check a node's feature/condition/inject map against its roles.

        ``defined`` is the scenario section keyed by the referenced name;
        ``section_label`` is the singular noun used in error messages.
        """
        for ref_name, role_name in ref_roles.items():
            if ref_name not in defined:
                self._err(
                    f"Node '{name}' references undefined {section_label} "
                    f"'{ref_name}'"
                )
            if (
                role_name
                and not self._is_unresolved_var(role_name)
                and role_name not in node.roles
            ):
                self._err(
                    f"Node '{name}' {section_label} '{ref_name}' references "
                    f"undefined role '{role_name}'"
                )

    def _verify_node(self, name: str, node: Node) -> None:
        """Validate a single node's name length and reference maps."""
        if len(name) > MAX_NODE_NAME_LENGTH:
            self._err(f"Node '{name}' name exceeds 35 characters")

        self._verify_node_role_refs(
            name, node, "feature", node.features, self._s.features
        )
        self._verify_node_role_refs(
            name, node, "condition", node.conditions, self._s.conditions
        )
        self._verify_node_role_refs(
            name, node, "inject", node.injects, self._s.injects
        )

        for vuln_name in node.vulnerabilities:
            if self._is_unresolved_var(vuln_name):
                continue
            if vuln_name not in self._s.vulnerabilities:
                self._err(
                    f"Node '{name}' references undefined vulnerability '{vuln_name}'"
                )

    def _verify_nodes(self) -> None:
        """Validate every node's references and naming constraints."""
        for name, node in self._s.nodes.items():
            self._verify_node(name, node)

    def _verify_infra_count(self, name: str, infra: InfraNode) -> None:
        """Reject count > 1 for switches and condition-bearing VM nodes."""
        node = self._s.nodes.get(name)
        if node is None or not isinstance(infra.count, int) or infra.count <= 1:
            return
        if node.type == NodeType.SWITCH:
            self._err(f"Switch node '{name}' cannot have count > 1")
        if node.type == NodeType.VM and node.conditions:
            self._err(
                f"Node '{name}' has conditions and cannot have count > 1"
            )

    def _link_network_cidr(self, name: str, link_name: str) -> str | None:
        """Return a switch link's CIDR string, or None when unusable.

        Records the switch/network and CIDR-properties errors as the original
        pass did; returns None whenever the IP check should be skipped (a
        recorded error, a missing link, or an unresolved CIDR variable).
        """
        cidr: str | None = None
        if not self._is_switch_node(link_name):
            self._err(
                f"Infrastructure '{name}' property link "
                f"'{link_name}' must reference a switch/network entry"
            )
            return cidr
        linked_infra = self._s.infrastructure.get(link_name)
        if linked_infra is None:
            return cidr
        if isinstance(linked_infra.properties, SimpleProperties):
            cidr = linked_infra.properties.cidr
        else:
            self._err(
                f"Infrastructure '{name}' property link "
                f"'{link_name}' must reference a network with CIDR "
                "properties"
            )
        return cidr

    def _check_ip_within_cidr(
        self, name: str, link_name: str, ip_str: str, cidr: str
    ) -> None:
        """Validate that ``ip_str`` parses and lies within ``cidr``."""
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            self._err(f"Infrastructure '{link_name}' has invalid CIDR {cidr}")
            return
        try:
            addr = ip_address(ip_str)
        except ValueError:
            self._err(
                f"Infrastructure '{name}' has invalid IP "
                f"assignment '{ip_str}' for link '{link_name}'"
            )
            return
        if addr not in net:
            self._err(
                f"Infrastructure '{name}' IP {ip_str} "
                f"not within '{link_name}' CIDR {cidr}"
            )

    def _verify_infra_property_ip(
        self, name: str, infra: InfraNode, link_name: str, ip_str: str
    ) -> None:
        """Validate one ``{link: ip}`` property assignment against its CIDR."""
        if self._is_unresolved_var(link_name):
            return
        if link_name not in infra.links:
            self._err(
                f"Infrastructure '{name}' property references "
                f"unlinked node '{link_name}'"
            )

        cidr = self._link_network_cidr(name, link_name)
        if cidr is None:
            return
        if self._is_unresolved_var(ip_str) or self._is_unresolved_var(cidr):
            return
        self._check_ip_within_cidr(name, link_name, ip_str, cidr)

    def _verify_infra_properties(self, name: str, infra: InfraNode) -> None:
        """Validate complex (list-of-dict) property IP assignments."""
        if isinstance(infra.properties, list):
            for prop_entry in infra.properties:
                for link_name, ip_str in prop_entry.items():
                    self._verify_infra_property_ip(name, infra, link_name, ip_str)

    def _verify_infra_acls(self, name: str, infra: InfraNode) -> None:
        """Validate ACL network references point at defined switch entries."""
        for acl in infra.acls:
            for ref in (acl.from_net, acl.to_net):
                if self._is_unresolved_var(ref):
                    continue
                if ref and ref not in self._s.infrastructure:
                    self._err(
                        f"Infrastructure '{name}' ACL references "
                        f"undefined network '{ref}'"
                    )
                elif ref and not self._is_switch_node(ref):
                    self._err(
                        f"Infrastructure '{name}' ACL reference '{ref}' "
                        "must point to a switch/network entry"
                    )

    def _verify_infra_links(self, name: str, infra: InfraNode) -> None:
        """Validate an infrastructure entry's links and dependencies."""
        for link in infra.links:
            if self._is_unresolved_var(link):
                continue
            if link not in self._s.infrastructure:
                self._err(
                    f"Infrastructure '{name}' links to undefined '{link}'"
                )
            elif not self._is_switch_node(link):
                self._err(
                    f"Infrastructure '{name}' link '{link}' must reference "
                    "a switch/network entry"
                )

        for dep in infra.dependencies:
            if self._is_unresolved_var(dep):
                continue
            if dep not in self._s.infrastructure:
                self._err(
                    f"Infrastructure '{name}' depends on undefined '{dep}'"
                )

    def _verify_infrastructure(self) -> None:
        """Validate every infrastructure entry and its references."""
        for name, infra in self._s.infrastructure.items():
            if name not in self._s.nodes:
                self._err(
                    f"Infrastructure '{name}' does not match any defined node"
                )

            self._verify_infra_links(name, infra)
            self._verify_infra_count(name, infra)
            self._verify_infra_properties(name, infra)
            self._verify_infra_acls(name, infra)

    def _verify_content(self) -> None:
        """Validate that content targets reference defined VM nodes."""
        for name, item in self._s.content.items():
            if (
                item.target
                and not self._is_unresolved_var(item.target)
                and item.target not in self._s.nodes
            ):
                self._err(
                    f"Content '{name}' targets undefined node '{item.target}'"
                )
            elif (
                item.target
                and not self._is_unresolved_var(item.target)
                and not self._is_vm_node(item.target)
            ):
                self._err(
                    f"Content '{name}' target '{item.target}' must be a VM node"
                )

    def _verify_accounts(self) -> None:
        """Validate that account node references are defined VM nodes."""
        for name, acct in self._s.accounts.items():
            if (
                acct.node
                and not self._is_unresolved_var(acct.node)
                and acct.node not in self._s.nodes
            ):
                self._err(
                    f"Account '{name}' references undefined node '{acct.node}'"
                )
            elif (
                acct.node
                and not self._is_unresolved_var(acct.node)
                and not self._is_vm_node(acct.node)
            ):
                self._err(
                    f"Account '{name}' node '{acct.node}' must be a VM node"
                )

    def _verify_roles(self) -> None:
        """Validate that node role entity references are defined entities."""
        flat_names = self._all_entity_names()

        for node_name, node in self._s.nodes.items():
            for role_name, role in node.roles.items():
                for entity_ref in role.entities:
                    if self._is_unresolved_var(entity_ref):
                        continue
                    if entity_ref not in flat_names:
                        self._err(
                            f"Node '{node_name}' role '{role_name}' references "
                            f"undefined entity '{entity_ref}'"
                        )
