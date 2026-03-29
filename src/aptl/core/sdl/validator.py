"""Semantic validation for SDL scenarios.

Goes beyond Pydantic structural checks to enforce cross-reference
integrity, dependency cycle detection, IP/CIDR consistency, and
domain-specific rules. Collects all errors rather than failing on
the first one.
"""

import re
from collections import defaultdict
from ipaddress import ip_address, ip_network

from aptl.core.sdl._errors import SDLValidationError
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario
from aptl.core.sdl.scoring import MetricType


def _topological_sort(graph: dict[str, list[str]]) -> list[str] | None:
    """Return topological order or None if a cycle exists."""
    in_degree: dict[str, int] = defaultdict(int)
    for node in graph:
        in_degree.setdefault(node, 0)
    for deps in graph.values():
        for dep in deps:
            in_degree[dep] += 1

    queue = [n for n, d in in_degree.items() if d == 0]
    order: list[str] = []

    while queue:
        node = queue.pop(0)
        order.append(node)
        for dep in graph.get(node, []):
            in_degree[dep] -= 1
            if in_degree[dep] == 0:
                queue.append(dep)

    return order if len(order) == len(in_degree) else None


class SemanticValidator:
    """Validates a Scenario beyond structural Pydantic checks.

    Call ``validate()`` to run all passes. Raises ``SDLValidationError``
    with all collected errors if any pass fails.
    """

    def __init__(self, scenario: Scenario) -> None:
        self._s = scenario
        self._errors: list[str] = []

    def _err(self, msg: str) -> None:
        self._errors.append(msg)

    def validate(self) -> None:
        """Run all validation passes and raise on errors."""
        self._errors = []

        # OCR passes
        self._verify_nodes()
        self._verify_infrastructure()
        self._verify_features()
        self._verify_conditions()
        self._verify_vulnerabilities()
        self._verify_metrics()
        self._verify_evaluations()
        self._verify_tlos()
        self._verify_goals()
        self._verify_entities()
        self._verify_injects()
        self._verify_events()
        self._verify_scripts()
        self._verify_stories()
        self._verify_roles()

        # New section passes
        self._verify_content()
        self._verify_accounts()
        self._verify_relationships()
        self._verify_agents()
        self._verify_variables()

        if self._errors:
            raise SDLValidationError(self._errors)

    # ------------------------------------------------------------------
    # OCR validation passes
    # ------------------------------------------------------------------

    def _verify_nodes(self) -> None:
        for name, node in self._s.nodes.items():
            if len(name) > 35:
                self._err(f"Node '{name}' name exceeds 35 characters")

            for feat_name, role_name in node.features.items():
                if feat_name not in self._s.features:
                    self._err(
                        f"Node '{name}' references undefined feature '{feat_name}'"
                    )
                if role_name and node.roles and role_name not in node.roles:
                    self._err(
                        f"Node '{name}' feature '{feat_name}' references "
                        f"undefined role '{role_name}'"
                    )

            for cond_name, role_name in node.conditions.items():
                if cond_name not in self._s.conditions:
                    self._err(
                        f"Node '{name}' references undefined condition '{cond_name}'"
                    )
                if role_name and node.roles and role_name not in node.roles:
                    self._err(
                        f"Node '{name}' condition '{cond_name}' references "
                        f"undefined role '{role_name}'"
                    )

            for inj_name, role_name in node.injects.items():
                if inj_name not in self._s.injects:
                    self._err(
                        f"Node '{name}' references undefined inject '{inj_name}'"
                    )
                if role_name and node.roles and role_name not in node.roles:
                    self._err(
                        f"Node '{name}' inject '{inj_name}' references "
                        f"undefined role '{role_name}'"
                    )

            for vuln_name in node.vulnerabilities:
                if vuln_name not in self._s.vulnerabilities:
                    self._err(
                        f"Node '{name}' references undefined vulnerability '{vuln_name}'"
                    )

    def _verify_infrastructure(self) -> None:
        for name, infra in self._s.infrastructure.items():
            if name not in self._s.nodes:
                self._err(
                    f"Infrastructure '{name}' does not match any defined node"
                )

            for link in infra.links:
                if link not in self._s.infrastructure:
                    self._err(
                        f"Infrastructure '{name}' links to undefined '{link}'"
                    )

            for dep in infra.dependencies:
                if dep not in self._s.infrastructure:
                    self._err(
                        f"Infrastructure '{name}' depends on undefined '{dep}'"
                    )

            # Switch nodes cannot have count > 1
            if name in self._s.nodes:
                if self._s.nodes[name].type == NodeType.SWITCH and infra.count > 1:
                    self._err(
                        f"Switch node '{name}' cannot have count > 1"
                    )

            # Validate complex properties IP within linked CIDR
            if isinstance(infra.properties, list):
                for prop_entry in infra.properties:
                    for link_name, ip_str in prop_entry.items():
                        if link_name not in infra.links:
                            self._err(
                                f"Infrastructure '{name}' property references "
                                f"unlinked node '{link_name}'"
                            )
                        # Check IP is within the linked node's CIDR
                        linked_infra = self._s.infrastructure.get(link_name)
                        if linked_infra and hasattr(linked_infra.properties, "cidr"):
                            try:
                                net = ip_network(
                                    linked_infra.properties.cidr, strict=False
                                )
                                addr = ip_address(ip_str)
                                if addr not in net:
                                    self._err(
                                        f"Infrastructure '{name}' IP {ip_str} "
                                        f"not within '{link_name}' CIDR "
                                        f"{linked_infra.properties.cidr}"
                                    )
                            except (ValueError, AttributeError):
                                pass

            # Validate ACL network references
            for acl in infra.acls:
                ref = acl.from_net or acl.to_net
                if ref and ref not in self._s.infrastructure:
                    self._err(
                        f"Infrastructure '{name}' ACL references "
                        f"undefined network '{ref}'"
                    )

    def _verify_content(self) -> None:
        for name, item in self._s.content.items():
            if item.target and item.target not in self._s.nodes:
                self._err(
                    f"Content '{name}' targets undefined node '{item.target}'"
                )

    def _verify_accounts(self) -> None:
        for name, acct in self._s.accounts.items():
            if acct.node and acct.node not in self._s.nodes:
                self._err(
                    f"Account '{name}' references undefined node '{acct.node}'"
                )

    def _verify_relationships(self) -> None:
        all_names = self._all_named_elements()
        for name, rel in self._s.relationships.items():
            if rel.source not in all_names:
                self._err(
                    f"Relationship '{name}' source '{rel.source}' "
                    f"does not reference any defined element"
                )
            if rel.target not in all_names:
                self._err(
                    f"Relationship '{name}' target '{rel.target}' "
                    f"does not reference any defined element"
                )

    def _verify_agents(self) -> None:
        flat_entity_names = set(flatten_entities(self._s.entities).keys())
        flat_entity_names.update(self._s.entities.keys())

        for name, agent in self._s.agents.items():
            if agent.entity and agent.entity not in flat_entity_names:
                self._err(
                    f"Agent '{name}' references undefined entity '{agent.entity}'"
                )
            for acct_name in agent.starting_accounts:
                if acct_name not in self._s.accounts:
                    self._err(
                        f"Agent '{name}' starting_account '{acct_name}' "
                        f"not in accounts section"
                    )
            for subnet in agent.allowed_subnets:
                if subnet not in self._s.infrastructure:
                    self._err(
                        f"Agent '{name}' allowed_subnet '{subnet}' "
                        f"not in infrastructure section"
                    )
            if agent.initial_knowledge:
                for host in agent.initial_knowledge.hosts:
                    if host not in self._s.nodes:
                        self._err(
                            f"Agent '{name}' initial_knowledge host '{host}' "
                            f"not in nodes section"
                        )
                for subnet in agent.initial_knowledge.subnets:
                    if subnet not in self._s.infrastructure:
                        self._err(
                            f"Agent '{name}' initial_knowledge subnet '{subnet}' "
                            f"not in infrastructure section"
                        )

    def _verify_variables(self) -> None:
        # Variable definitions are structurally validated by Pydantic.
        # Cross-reference validation (checking ${var} references in other
        # sections) is deferred to instantiation time because variable
        # substitution strings can appear in any string field.
        pass

    def _all_named_elements(self) -> set[str]:
        """Collect all named element keys across all scenario sections."""
        names: set[str] = set()
        names.update(self._s.nodes.keys())
        names.update(self._s.features.keys())
        names.update(self._s.conditions.keys())
        names.update(self._s.vulnerabilities.keys())
        names.update(self._s.infrastructure.keys())
        names.update(self._s.metrics.keys())
        names.update(self._s.evaluations.keys())
        names.update(self._s.tlos.keys())
        names.update(self._s.goals.keys())
        names.update(self._s.entities.keys())
        names.update(flatten_entities(self._s.entities).keys())
        names.update(self._s.injects.keys())
        names.update(self._s.events.keys())
        names.update(self._s.scripts.keys())
        names.update(self._s.stories.keys())
        names.update(self._s.content.keys())
        names.update(self._s.accounts.keys())
        names.update(self._s.agents.keys())
        return names

    def _verify_features(self) -> None:
        # Check vulnerability references
        for name, feat in self._s.features.items():
            for vuln_name in feat.vulnerabilities:
                if vuln_name not in self._s.vulnerabilities:
                    self._err(
                        f"Feature '{name}' references undefined vulnerability "
                        f"'{vuln_name}'"
                    )

        # Check dependency references and detect cycles
        dep_graph: dict[str, list[str]] = {}
        for name, feat in self._s.features.items():
            dep_graph[name] = []
            for dep in feat.dependencies:
                if dep not in self._s.features:
                    self._err(
                        f"Feature '{name}' depends on undefined feature '{dep}'"
                    )
                else:
                    dep_graph[name].append(dep)

        if dep_graph and _topological_sort(dep_graph) is None:
            self._err("Feature dependency graph contains a cycle")

    def _verify_conditions(self) -> None:
        # Individual condition validation is handled by Pydantic model_validator.
        # This pass checks for consistency with the broader scenario.
        pass

    def _verify_vulnerabilities(self) -> None:
        # CWE format validation is handled by the Pydantic field_validator.
        pass

    def _verify_metrics(self) -> None:
        used_conditions: set[str] = set()

        for name, metric in self._s.metrics.items():
            if metric.type == MetricType.CONDITIONAL:
                cond = metric.condition
                if cond and cond not in self._s.conditions:
                    self._err(
                        f"Metric '{name}' references undefined condition '{cond}'"
                    )
                if cond in used_conditions:
                    self._err(
                        f"Condition '{cond}' is referenced by multiple metrics"
                    )
                if cond:
                    used_conditions.add(cond)

    def _verify_evaluations(self) -> None:
        for name, evaluation in self._s.evaluations.items():
            max_total = 0
            for metric_name in evaluation.metrics:
                if metric_name not in self._s.metrics:
                    self._err(
                        f"Evaluation '{name}' references undefined metric "
                        f"'{metric_name}'"
                    )
                else:
                    max_total += self._s.metrics[metric_name].max_score

            if evaluation.min_score.absolute is not None:
                if evaluation.min_score.absolute > max_total:
                    self._err(
                        f"Evaluation '{name}' absolute min-score "
                        f"({evaluation.min_score.absolute}) exceeds sum of "
                        f"metric max-scores ({max_total})"
                    )

    def _verify_tlos(self) -> None:
        for name, tlo in self._s.tlos.items():
            if tlo.evaluation not in self._s.evaluations:
                self._err(
                    f"TLO '{name}' references undefined evaluation "
                    f"'{tlo.evaluation}'"
                )

    def _verify_goals(self) -> None:
        for name, goal in self._s.goals.items():
            for tlo_name in goal.tlos:
                if tlo_name not in self._s.tlos:
                    self._err(
                        f"Goal '{name}' references undefined TLO '{tlo_name}'"
                    )

    def _verify_entities(self) -> None:
        flat = flatten_entities(self._s.entities)

        def check_entity(name: str, entity: "Entity") -> None:
            for tlo_name in entity.tlos:
                if tlo_name not in self._s.tlos:
                    self._err(
                        f"Entity '{name}' references undefined TLO '{tlo_name}'"
                    )
            for vuln_name in entity.vulnerabilities:
                if vuln_name not in self._s.vulnerabilities:
                    self._err(
                        f"Entity '{name}' references undefined vulnerability "
                        f"'{vuln_name}'"
                    )
            for event_name in entity.events:
                if event_name not in self._s.events:
                    self._err(
                        f"Entity '{name}' references undefined event "
                        f"'{event_name}'"
                    )

        for name, entity in flat.items():
            check_entity(name, entity)

    def _verify_injects(self) -> None:
        flat_names = set(flatten_entities(self._s.entities).keys())
        # Also include top-level entity keys
        flat_names.update(self._s.entities.keys())

        for name, inject in self._s.injects.items():
            if inject.from_entity and inject.from_entity not in flat_names:
                self._err(
                    f"Inject '{name}' from_entity '{inject.from_entity}' "
                    f"is not a defined entity"
                )
            for to_name in inject.to_entities:
                if to_name not in flat_names:
                    self._err(
                        f"Inject '{name}' to_entity '{to_name}' "
                        f"is not a defined entity"
                    )
            for tlo_name in inject.tlos:
                if tlo_name not in self._s.tlos:
                    self._err(
                        f"Inject '{name}' references undefined TLO '{tlo_name}'"
                    )

    def _verify_events(self) -> None:
        for name, event in self._s.events.items():
            for cond_name in event.conditions:
                if cond_name not in self._s.conditions:
                    self._err(
                        f"Event '{name}' references undefined condition "
                        f"'{cond_name}'"
                    )
            for inj_name in event.injects:
                if inj_name not in self._s.injects:
                    self._err(
                        f"Event '{name}' references undefined inject '{inj_name}'"
                    )

    def _verify_scripts(self) -> None:
        for name, script in self._s.scripts.items():
            for event_name in script.events:
                if event_name not in self._s.events:
                    self._err(
                        f"Script '{name}' references undefined event "
                        f"'{event_name}'"
                    )

    def _verify_stories(self) -> None:
        for name, story in self._s.stories.items():
            for script_name in story.scripts:
                if script_name not in self._s.scripts:
                    self._err(
                        f"Story '{name}' references undefined script "
                        f"'{script_name}'"
                    )

    def _verify_roles(self) -> None:
        flat_names = set(flatten_entities(self._s.entities).keys())
        flat_names.update(self._s.entities.keys())

        for node_name, node in self._s.nodes.items():
            for role_name, role in node.roles.items():
                for entity_ref in role.entities:
                    if entity_ref not in flat_names:
                        self._err(
                            f"Node '{node_name}' role '{role_name}' references "
                            f"undefined entity '{entity_ref}'"
                        )
