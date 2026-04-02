"""Semantic validation for SDL scenarios.

Goes beyond Pydantic structural checks to enforce cross-reference
integrity, dependency cycle detection, IP/CIDR consistency, and
domain-specific rules. Collects all errors rather than failing on
the first one.
"""

from collections import defaultdict, deque
from ipaddress import ip_address, ip_network

from pydantic import BaseModel

from aptl.core.semantics.objectives import analyze_objective_window
from aptl.core.semantics.workflow import (
    branch_closure,
    workflow_step_semantic_contract,
)
from aptl.core.sdl._errors import SDLValidationError
from aptl.core.sdl._base import extract_variable_name, is_variable_ref
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.infrastructure import SimpleProperties
from aptl.core.sdl.nodes import MAX_NODE_NAME_LENGTH, NodeType
from aptl.core.sdl.orchestration import WorkflowPredicate, WorkflowStep, WorkflowStepType
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

    queue = deque(n for n, d in in_degree.items() if d == 0)
    order: list[str] = []

    while queue:
        node = queue.popleft()
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
        self._warnings: list[str] = []

    def _err(self, msg: str) -> None:
        self._errors.append(msg)

    def _warn(self, msg: str) -> None:
        self._warnings.append(msg)

    def _is_unresolved_var(self, value: object) -> bool:
        return is_variable_ref(value)

    def _node_type(self, node_name: str) -> NodeType | None:
        node = self._s.nodes.get(node_name)
        return node.type if node is not None else None

    def _is_switch_node(self, node_name: str) -> bool:
        return self._node_type(node_name) == NodeType.SWITCH

    def _is_vm_node(self, node_name: str) -> bool:
        return self._node_type(node_name) == NodeType.VM

    def _all_entity_names(self) -> set[str]:
        return set(flatten_entities(self._s.entities).keys())

    def _qualified_service_refs(self) -> set[str]:
        refs: set[str] = set()
        for node_name, node in self._s.nodes.items():
            for service in node.services:
                if service.name:
                    refs.add(f"nodes.{node_name}.services.{service.name}")
        return refs

    def _qualified_acl_refs(self) -> set[str]:
        refs: set[str] = set()
        for infra_name, infra in self._s.infrastructure.items():
            for acl in infra.acls:
                if acl.name:
                    refs.add(f"infrastructure.{infra_name}.acls.{acl.name}")
        return refs

    def _workflow_step_refs(self) -> set[str]:
        refs: set[str] = set()
        for workflow_name, workflow in self._s.workflows.items():
            for step_name in workflow.steps:
                refs.add(f"{workflow_name}.{step_name}")
        return refs

    def _named_ref_index(self, *, targetable: bool = False) -> dict[str, set[str]]:
        """Build the alias map for generic relationship/objective refs.

        Bare refs stay available for most top-level sections when they are
        unambiguous. Qualified refs are always accepted for top-level sections,
        and are required for infrastructure entries because those keys
        intentionally mirror node names.
        """
        index: dict[str, set[str]] = defaultdict(set)

        def add(alias: str, canonical: str) -> None:
            index[alias].add(canonical)

        top_level_sections = (
            ("nodes", self._s.nodes, True),
            ("features", self._s.features, True),
            ("conditions", self._s.conditions, True),
            ("vulnerabilities", self._s.vulnerabilities, True),
            ("infrastructure", self._s.infrastructure, False),
            ("metrics", self._s.metrics, True),
            ("evaluations", self._s.evaluations, True),
            ("tlos", self._s.tlos, True),
            ("goals", self._s.goals, True),
            ("content", self._s.content, True),
            ("accounts", self._s.accounts, True),
            ("agents", self._s.agents, True),
            ("objectives", self._s.objectives, True),
            ("workflows", self._s.workflows, True),
            ("relationships", self._s.relationships, True),
            ("variables", self._s.variables, True),
            ("injects", self._s.injects, True),
            ("events", self._s.events, True),
            ("scripts", self._s.scripts, True),
            ("stories", self._s.stories, True),
        )

        for section_name, section, allow_bare in top_level_sections:
            for name in section:
                canonical = f"{section_name}.{name}"
                add(canonical, canonical)
                if allow_bare:
                    add(name, canonical)

        for entity_name in self._all_entity_names():
            canonical = f"entities.{entity_name}"
            add(canonical, canonical)
            add(entity_name, canonical)

        for content_name, content in self._s.content.items():
            for item in content.items:
                if not item.name:
                    continue
                canonical = f"content.{content_name}.items.{item.name}"
                add(canonical, canonical)
                add(item.name, canonical)

        for ref in self._qualified_service_refs():
            add(ref, ref)
        for ref in self._qualified_acl_refs():
            add(ref, ref)

        if not targetable:
            return {alias: set(candidates) for alias, candidates in index.items()}

        disallowed_prefixes = (
            "variables.",
            "objectives.",
            "workflows.",
        )
        filtered: dict[str, set[str]] = {}
        for alias, candidates in index.items():
            keep = {
                candidate
                for candidate in candidates
                if not candidate.startswith(disallowed_prefixes)
            }
            if keep:
                filtered[alias] = keep
        return filtered

    def _validate_named_ref(
        self,
        ref: str,
        *,
        owner_label: str,
        ref_label: str,
        targetable: bool = False,
    ) -> None:
        """Validate a generic reference against the named-element index."""
        index = self._named_ref_index(targetable=targetable)
        candidates = index.get(ref)
        if not candidates:
            qualifier = "targetable " if targetable else ""
            self._err(
                f"{owner_label} {ref_label} '{ref}' does not reference any "
                f"defined {qualifier}element"
            )
            return

        if len(candidates) > 1:
            choices = ", ".join(sorted(candidates))
            self._err(
                f"{owner_label} {ref_label} '{ref}' is ambiguous; use one of: "
                f"{choices}"
            )

    def validate(self) -> None:
        """Run all validation passes and raise on errors."""
        self._errors = []
        self._warnings = []

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
        self._verify_objectives()
        self._verify_workflows()
        self._verify_variables()
        self._collect_advisories()

        if self._errors:
            raise SDLValidationError(self._errors)

    @property
    def warnings(self) -> list[str]:
        """Return non-fatal advisories collected during validation."""
        return list(self._warnings)

    def _collect_advisories(self) -> None:
        self._warn_missing_vm_resources()

    def _warn_missing_vm_resources(self) -> None:
        for name, node in self._s.nodes.items():
            if node.type != NodeType.VM:
                continue
            if node.resources is None:
                self._warn(
                    f"Node '{name}' is a VM without 'resources'. This is "
                    "valid SDL, but may be undeployable unless the backend "
                    "supplies defaults."
                )

    # ------------------------------------------------------------------
    # OCR validation passes
    # ------------------------------------------------------------------

    def _verify_nodes(self) -> None:
        for name, node in self._s.nodes.items():
            if len(name) > MAX_NODE_NAME_LENGTH:
                self._err(f"Node '{name}' name exceeds 35 characters")

            for feat_name, role_name in node.features.items():
                if feat_name not in self._s.features:
                    self._err(
                        f"Node '{name}' references undefined feature '{feat_name}'"
                    )
                if (
                    role_name
                    and not self._is_unresolved_var(role_name)
                    and role_name not in node.roles
                ):
                    self._err(
                        f"Node '{name}' feature '{feat_name}' references "
                        f"undefined role '{role_name}'"
                    )

            for cond_name, role_name in node.conditions.items():
                if cond_name not in self._s.conditions:
                    self._err(
                        f"Node '{name}' references undefined condition '{cond_name}'"
                    )
                if (
                    role_name
                    and not self._is_unresolved_var(role_name)
                    and role_name not in node.roles
                ):
                    self._err(
                        f"Node '{name}' condition '{cond_name}' references "
                        f"undefined role '{role_name}'"
                    )

            for inj_name, role_name in node.injects.items():
                if inj_name not in self._s.injects:
                    self._err(
                        f"Node '{name}' references undefined inject '{inj_name}'"
                    )
                if (
                    role_name
                    and not self._is_unresolved_var(role_name)
                    and role_name not in node.roles
                ):
                    self._err(
                        f"Node '{name}' inject '{inj_name}' references "
                        f"undefined role '{role_name}'"
                    )

            for vuln_name in node.vulnerabilities:
                if self._is_unresolved_var(vuln_name):
                    continue
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

            # Switch nodes cannot have count > 1
            if name in self._s.nodes:
                if (
                    self._s.nodes[name].type == NodeType.SWITCH
                    and isinstance(infra.count, int)
                    and infra.count > 1
                ):
                    self._err(
                        f"Switch node '{name}' cannot have count > 1"
                    )
                if (
                    self._s.nodes[name].type == NodeType.VM
                    and self._s.nodes[name].conditions
                    and isinstance(infra.count, int)
                    and infra.count > 1
                ):
                    self._err(
                        f"Node '{name}' has conditions and cannot have count > 1"
                    )

            # Validate complex properties IP within linked CIDR
            if isinstance(infra.properties, list):
                for prop_entry in infra.properties:
                    for link_name, ip_str in prop_entry.items():
                        if self._is_unresolved_var(link_name):
                            continue
                        if link_name not in infra.links:
                            self._err(
                                f"Infrastructure '{name}' property references "
                                f"unlinked node '{link_name}'"
                            )
                        if not self._is_switch_node(link_name):
                            self._err(
                                f"Infrastructure '{name}' property link "
                                f"'{link_name}' must reference a switch/network entry"
                            )
                            continue
                        # Check IP is within the linked node's CIDR
                        linked_infra = self._s.infrastructure.get(link_name)
                        if linked_infra is None:
                            continue
                        if not isinstance(linked_infra.properties, SimpleProperties):
                            self._err(
                                f"Infrastructure '{name}' property link "
                                f"'{link_name}' must reference a network with CIDR "
                                "properties"
                            )
                            continue
                        if self._is_unresolved_var(ip_str):
                            continue
                        if self._is_unresolved_var(linked_infra.properties.cidr):
                            continue
                        try:
                            net = ip_network(
                                linked_infra.properties.cidr, strict=False
                            )
                        except ValueError:
                            self._err(
                                f"Infrastructure '{link_name}' has invalid CIDR "
                                f"{linked_infra.properties.cidr}"
                            )
                            continue
                        try:
                            addr = ip_address(ip_str)
                        except ValueError:
                            self._err(
                                f"Infrastructure '{name}' has invalid IP "
                                f"assignment '{ip_str}' for link '{link_name}'"
                            )
                            continue
                        if addr not in net:
                            self._err(
                                f"Infrastructure '{name}' IP {ip_str} "
                                f"not within '{link_name}' CIDR "
                                f"{linked_infra.properties.cidr}"
                            )

            # Validate ACL network references
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

    def _verify_content(self) -> None:
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

    def _verify_relationships(self) -> None:
        for name, rel in self._s.relationships.items():
            if not self._is_unresolved_var(rel.source):
                self._validate_named_ref(
                    rel.source,
                    owner_label=f"Relationship '{name}'",
                    ref_label="source",
                )
            if not self._is_unresolved_var(rel.target):
                self._validate_named_ref(
                    rel.target,
                    owner_label=f"Relationship '{name}'",
                    ref_label="target",
                )

    def _verify_agents(self) -> None:
        flat_entity_names = self._all_entity_names()
        service_names = {
            service.name
            for node in self._s.nodes.values()
            for service in node.services
            if service.name
        }

        for name, agent in self._s.agents.items():
            if (
                agent.entity
                and not self._is_unresolved_var(agent.entity)
                and agent.entity not in flat_entity_names
            ):
                self._err(
                    f"Agent '{name}' references undefined entity '{agent.entity}'"
                )
            for acct_name in agent.starting_accounts:
                if self._is_unresolved_var(acct_name):
                    continue
                if acct_name not in self._s.accounts:
                    self._err(
                        f"Agent '{name}' starting_account '{acct_name}' "
                        f"not in accounts section"
                    )
            for subnet in agent.allowed_subnets:
                if self._is_unresolved_var(subnet):
                    continue
                if subnet not in self._s.infrastructure:
                    self._err(
                        f"Agent '{name}' allowed_subnet '{subnet}' "
                        f"not in infrastructure section"
                    )
                elif not self._is_switch_node(subnet):
                    self._err(
                        f"Agent '{name}' allowed_subnet '{subnet}' must "
                        "reference a switch/network entry"
                    )
            if agent.initial_knowledge:
                for host in agent.initial_knowledge.hosts:
                    if self._is_unresolved_var(host):
                        continue
                    if host not in self._s.nodes:
                        self._err(
                            f"Agent '{name}' initial_knowledge host '{host}' "
                            f"not in nodes section"
                        )
                    elif not self._is_vm_node(host):
                        self._err(
                            f"Agent '{name}' initial_knowledge host '{host}' "
                            "must reference a VM node"
                        )
                for subnet in agent.initial_knowledge.subnets:
                    if self._is_unresolved_var(subnet):
                        continue
                    if subnet not in self._s.infrastructure:
                        self._err(
                            f"Agent '{name}' initial_knowledge subnet '{subnet}' "
                            f"not in infrastructure section"
                        )
                    elif not self._is_switch_node(subnet):
                        self._err(
                            f"Agent '{name}' initial_knowledge subnet "
                            f"'{subnet}' must reference a switch/network entry"
                        )
                for service_name in agent.initial_knowledge.services:
                    if self._is_unresolved_var(service_name):
                        continue
                    if service_name not in service_names:
                        self._err(
                            f"Agent '{name}' initial_knowledge service "
                            f"'{service_name}' not in node service names"
                        )
                for acct_name in agent.initial_knowledge.accounts:
                    if self._is_unresolved_var(acct_name):
                        continue
                    if acct_name not in self._s.accounts:
                        self._err(
                            f"Agent '{name}' initial_knowledge account "
                            f"'{acct_name}' not in accounts section"
                        )

    def _verify_objectives(self) -> None:
        actor_entities = self._all_entity_names()

        for name, objective in self._s.objectives.items():
            if (
                objective.agent
                and not self._is_unresolved_var(objective.agent)
                and objective.agent not in self._s.agents
            ):
                self._err(
                    f"Objective '{name}' references undefined agent "
                    f"'{objective.agent}'"
                )

            if (
                objective.entity
                and not self._is_unresolved_var(objective.entity)
                and objective.entity not in actor_entities
            ):
                self._err(
                    f"Objective '{name}' references undefined entity "
                    f"'{objective.entity}'"
                )

            if (
                objective.agent
                and not self._is_unresolved_var(objective.agent)
                and objective.agent in self._s.agents
            ):
                allowed_actions = set(self._s.agents[objective.agent].actions)
                for action in objective.actions:
                    if self._is_unresolved_var(action):
                        continue
                    if action not in allowed_actions:
                        self._err(
                            f"Objective '{name}' action '{action}' is not "
                            f"declared by agent '{objective.agent}'"
                        )

            for target in objective.targets:
                if self._is_unresolved_var(target):
                    continue
                self._validate_named_ref(
                    target,
                    owner_label=f"Objective '{name}'",
                    ref_label="target",
                    targetable=True,
                )

            success_sections = (
                ("condition", objective.success.conditions, self._s.conditions),
                ("metric", objective.success.metrics, self._s.metrics),
                ("evaluation", objective.success.evaluations, self._s.evaluations),
                ("TLO", objective.success.tlos, self._s.tlos),
                ("goal", objective.success.goals, self._s.goals),
            )
            for label, refs, section in success_sections:
                for ref in refs:
                    if self._is_unresolved_var(ref):
                        continue
                    if ref not in section:
                        self._err(
                            f"Objective '{name}' references undefined {label} "
                            f"'{ref}' in success criteria"
                        )

            if objective.window:
                window_analysis = analyze_objective_window(
                    story_refs=[
                        story_name
                        for story_name in objective.window.stories
                        if not self._is_unresolved_var(story_name)
                    ],
                    script_refs=[
                        script_name
                        for script_name in objective.window.scripts
                        if not self._is_unresolved_var(script_name)
                    ],
                    event_refs=[
                        event_name
                        for event_name in objective.window.events
                        if not self._is_unresolved_var(event_name)
                    ],
                    workflow_refs=[
                        workflow_name
                        for workflow_name in objective.window.workflows
                        if not self._is_unresolved_var(workflow_name)
                    ],
                    step_refs=[
                        step_ref
                        for step_ref in objective.window.steps
                        if not self._is_unresolved_var(step_ref)
                    ],
                    stories_by_name=self._s.stories,
                    scripts_by_name=self._s.scripts,
                    events_by_name=self._s.events,
                    workflows_by_name=self._s.workflows,
                )

                for issue in window_analysis.issues:
                    if issue.code == "story-unbound":
                        self._err(
                            f"Objective '{name}' references undefined story "
                            f"'{issue.ref}' in window"
                        )
                    elif issue.code == "script-unbound":
                        self._err(
                            f"Objective '{name}' references undefined script "
                            f"'{issue.ref}' in window"
                        )
                    elif issue.code == "script-outside-window-stories":
                        self._err(
                            f"Objective '{name}' window script '{issue.ref}' "
                            "is not included by the referenced stories"
                        )
                    elif issue.code == "event-unbound":
                        self._err(
                            f"Objective '{name}' references undefined event "
                            f"'{issue.ref}' in window"
                        )
                    elif issue.code == "event-outside-window-scripts":
                        self._err(
                            f"Objective '{name}' window event '{issue.ref}' "
                            "is not included by the referenced scripts"
                        )
                    elif issue.code == "workflow-unbound":
                        self._err(
                            f"Objective '{name}' references undefined workflow "
                            f"'{issue.ref}' in window"
                        )
                    elif issue.code == "step-requires-workflow-window":
                        self._err(
                            f"Objective '{name}' window steps require at least one "
                            "referenced workflow"
                        )
                    elif issue.code == "step-invalid-format":
                        self._err(
                            f"Objective '{name}' window step '{issue.ref}' must "
                            "use '<workflow>.<step>' syntax"
                        )
                    elif issue.code == "step-workflow-unbound":
                        self._err(
                            f"Objective '{name}' window step '{issue.ref}' "
                            f"references undefined workflow '{issue.workflow_name}'"
                        )
                    elif issue.code == "step-workflow-outside-window":
                        self._err(
                            f"Objective '{name}' window step '{issue.ref}' "
                            "is not part of the referenced workflows"
                        )
                    elif issue.code == "step-unbound":
                        self._err(
                            f"Objective '{name}' window step '{issue.ref}' "
                            f"references undefined step '{issue.step_name}'"
                        )

            for dep_name in objective.depends_on:
                if self._is_unresolved_var(dep_name):
                    continue
                if dep_name not in self._s.objectives:
                    self._err(
                        f"Objective '{name}' depends on undefined objective "
                        f"'{dep_name}'"
                    )

        dep_graph: dict[str, list[str]] = {}
        for name, objective in self._s.objectives.items():
            dep_graph[name] = [
                dep for dep in objective.depends_on
                if not self._is_unresolved_var(dep) and dep in self._s.objectives
            ]
        if dep_graph and _topological_sort(dep_graph) is None:
            self._err("Objective dependency graph contains a cycle")

    def _validate_workflow_predicate(
        self,
        workflow_name: str,
        step_name: str,
        predicate: WorkflowPredicate,
        workflow_steps: dict[str, WorkflowStep],
    ) -> list[str]:
        """Validate all references within a workflow predicate."""
        step_refs: list[str] = []
        predicate_sections = (
            ("condition", predicate.conditions, self._s.conditions),
            ("metric", predicate.metrics, self._s.metrics),
            ("evaluation", predicate.evaluations, self._s.evaluations),
            ("TLO", predicate.tlos, self._s.tlos),
            ("goal", predicate.goals, self._s.goals),
            ("objective", predicate.objectives, self._s.objectives),
        )
        for label, refs, section in predicate_sections:
            for ref in refs:
                if self._is_unresolved_var(ref):
                    continue
                if ref not in section:
                    self._err(
                        f"Workflow '{workflow_name}' step "
                        f"'{step_name}' references undefined "
                        f"{label} '{ref}' in predicate"
                    )
        for step_state in predicate.steps:
            if self._is_unresolved_var(step_state.step):
                continue
            if step_state.step not in workflow_steps:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"references undefined step state "
                    f"'{step_state.step}' in predicate"
                )
                continue
            if step_state.step == step_name:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    "cannot reference its own state in a predicate"
                )
                continue
            ref_step = workflow_steps[step_state.step]
            contract = workflow_step_semantic_contract(ref_step.type.value)
            if not contract.state_observable:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"cannot reference non-executable step '{step_state.step}' "
                    "in a predicate"
                )
                continue
            invalid_outcomes = [
                outcome.value
                for outcome in step_state.outcomes
                if outcome.value not in contract.observable_outcomes
            ]
            if invalid_outcomes:
                allowed = ", ".join(contract.observable_outcomes)
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"references step '{step_state.step}' with impossible "
                    f"outcomes {invalid_outcomes}; allowed outcomes are: {allowed}"
                )
                continue
            step_refs.append(step_state.step)
        return step_refs

    def _is_executable_workflow_step(self, step: WorkflowStep) -> bool:
        return workflow_step_semantic_contract(step.type.value).state_observable

    def _validate_workflow_target_ref(
        self,
        workflow_name: str,
        step_name: str,
        field_name: str,
        target: str,
        workflow_steps: dict[str, WorkflowStep],
    ) -> str | None:
        if not target:
            return None
        if self._is_unresolved_var(target):
            return None
        if target not in workflow_steps:
            self._err(
                f"Workflow '{workflow_name}' step '{step_name}' "
                f"{field_name} step '{target}' is not defined"
            )
            return None
        return target

    def _all_paths_reach_join(
        self,
        node: str,
        join: str,
        graph: dict[str, list[str]],
        *,
        memo: dict[str, bool],
        visiting: set[str],
    ) -> bool:
        if node == join:
            return True
        if node in memo:
            return memo[node]
        if node in visiting:
            return False

        visiting.add(node)
        successors = graph.get(node, [])
        if not successors:
            visiting.remove(node)
            memo[node] = False
            return False

        result = all(
            self._all_paths_reach_join(
                successor,
                join,
                graph,
                memo=memo,
                visiting=visiting,
            )
            for successor in successors
        )
        visiting.remove(node)
        memo[node] = result
        return result

    def _branch_guaranteed_states(
        self,
        node: str,
        join: str,
        graph: dict[str, list[str]],
        workflow_steps: dict[str, WorkflowStep],
        *,
        memo: dict[tuple[str, str], set[str]],
        visiting: set[tuple[str, str]],
    ) -> set[str]:
        if node == join:
            return set()

        key = (node, join)
        if key in memo:
            return set(memo[key])
        if key in visiting:
            return set()

        visiting.add(key)
        successors = graph.get(node, [])
        guaranteed_after: set[str] = set()
        if successors:
            successor_sets: list[set[str]] = []
            for successor in successors:
                if successor == join:
                    successor_sets.append(set())
                    continue
                if successor not in workflow_steps:
                    continue
                successor_sets.append(
                    self._branch_guaranteed_states(
                        successor,
                        join,
                        graph,
                        workflow_steps,
                        memo=memo,
                        visiting=visiting,
                    )
                )
            if successor_sets:
                guaranteed_after = set.intersection(*successor_sets)

        result = set(guaranteed_after)
        step = workflow_steps[node]
        if self._is_executable_workflow_step(step):
            result.add(node)

        visiting.remove(key)
        memo[key] = set(result)
        return result

    def _edge_available_state(
        self,
        step_name: str,
        successor: str,
        workflow_steps: dict[str, WorkflowStep],
        graph: dict[str, list[str]],
        predecessors: dict[str, set[str]],
        start: str,
        join_targets: dict[str, list[str]],
        *,
        available_memo: dict[str, set[str]],
        branch_memo: dict[tuple[str, str], set[str]],
        visiting: set[str],
    ) -> set[str]:
        available = self._available_step_state_before(
            step_name,
            workflow_steps,
            graph,
            predecessors,
            start,
            join_targets,
            available_memo=available_memo,
            branch_memo=branch_memo,
            visiting=visiting,
        )
        step = workflow_steps[step_name]
        if step.type in {WorkflowStepType.OBJECTIVE, WorkflowStepType.RETRY}:
            available.add(step_name)
        elif (
            step.type == WorkflowStepType.PARALLEL
            and step.on_failure
            and successor == step.on_failure
        ):
            available.add(step_name)
        return available

    def _available_step_state_before(
        self,
        step_name: str,
        workflow_steps: dict[str, WorkflowStep],
        graph: dict[str, list[str]],
        predecessors: dict[str, set[str]],
        start: str,
        join_targets: dict[str, list[str]],
        *,
        available_memo: dict[str, set[str]],
        branch_memo: dict[tuple[str, str], set[str]],
        visiting: set[str],
    ) -> set[str]:
        if step_name in available_memo:
            return set(available_memo[step_name])
        if step_name in visiting:
            return set()

        visiting.add(step_name)
        step = workflow_steps[step_name]

        if step_name == start:
            result = set()
        elif step.type == WorkflowStepType.JOIN and join_targets.get(step_name):
            owner = join_targets[step_name][0]
            result = self._available_step_state_before(
                owner,
                workflow_steps,
                graph,
                predecessors,
                start,
                join_targets,
                available_memo=available_memo,
                branch_memo=branch_memo,
                visiting=visiting,
            )
            result.add(owner)
            owner_step = workflow_steps[owner]
            for branch in owner_step.branches:
                if branch not in workflow_steps:
                    continue
                result.update(
                    self._branch_guaranteed_states(
                        branch,
                        step_name,
                        graph,
                        workflow_steps,
                        memo=branch_memo,
                        visiting=set(),
                    )
                )
        else:
            incoming_states: list[set[str]] = []
            for predecessor in predecessors.get(step_name, set()):
                if predecessor not in workflow_steps:
                    continue
                incoming_states.append(
                    self._edge_available_state(
                        predecessor,
                        step_name,
                        workflow_steps,
                        graph,
                        predecessors,
                        start,
                        join_targets,
                        available_memo=available_memo,
                        branch_memo=branch_memo,
                        visiting=visiting,
                    )
                )
            result = set.intersection(*incoming_states) if incoming_states else set()

        visiting.remove(step_name)
        available_memo[step_name] = set(result)
        return result

    def _verify_workflows(self) -> None:
        for workflow_name, workflow in self._s.workflows.items():
            if "." in workflow_name:
                self._err(
                    f"Workflow '{workflow_name}' name cannot contain '.' "
                    "because step references use '<workflow>.<step>' syntax"
                )

            if (
                not self._is_unresolved_var(workflow.start)
                and workflow.start not in workflow.steps
            ):
                self._err(
                    f"Workflow '{workflow_name}' start step "
                    f"'{workflow.start}' is not defined"
                )

            graph: dict[str, list[str]] = {
                step_name: [] for step_name in workflow.steps
            }
            predicate_step_refs: dict[str, list[str]] = {}
            join_targets: dict[str, list[str]] = defaultdict(list)

            for step_name, step in workflow.steps.items():
                if "." in step_name:
                    self._err(
                        f"Workflow '{workflow_name}' step '{step_name}' cannot "
                        "contain '.' because objective windows use "
                        "'<workflow>.<step>' syntax"
                    )

                if step.type == WorkflowStepType.OBJECTIVE:
                    if (
                        not self._is_unresolved_var(step.objective)
                        and step.objective not in self._s.objectives
                    ):
                        self._err(
                            f"Workflow '{workflow_name}' step '{step_name}' "
                            f"references undefined objective '{step.objective}'"
                        )
                    for field_name, target in (
                        ("on-success", step.on_success),
                        ("on-failure", step.on_failure),
                    ):
                        resolved = self._validate_workflow_target_ref(
                            workflow_name,
                            step_name,
                            field_name,
                            target,
                            workflow.steps,
                        )
                        if resolved is not None:
                            graph[step_name].append(resolved)

                elif step.type == WorkflowStepType.DECISION:
                    predicate_step_refs[step_name] = self._validate_workflow_predicate(
                        workflow_name, step_name, step.when, workflow.steps,
                    )

                    for branch_label, branch_ref in (
                        ("then", step.then_step),
                        ("else", step.else_step),
                    ):
                        resolved = self._validate_workflow_target_ref(
                            workflow_name,
                            step_name,
                            branch_label,
                            branch_ref,
                            workflow.steps,
                        )
                        if resolved is not None:
                            graph[step_name].append(resolved)

                elif step.type == WorkflowStepType.PARALLEL:
                    for branch_ref in step.branches:
                        resolved = self._validate_workflow_target_ref(
                            workflow_name,
                            step_name,
                            "branch",
                            branch_ref,
                            workflow.steps,
                        )
                        if resolved is not None:
                            graph[step_name].append(resolved)
                    resolved_join = self._validate_workflow_target_ref(
                        workflow_name,
                        step_name,
                        "join",
                        step.join,
                        workflow.steps,
                    )
                    if resolved_join is not None:
                        join_targets[resolved_join].append(step_name)
                    resolved_failure = self._validate_workflow_target_ref(
                        workflow_name,
                        step_name,
                        "on-failure",
                        step.on_failure,
                        workflow.steps,
                    )
                    if resolved_failure is not None:
                        graph[step_name].append(resolved_failure)

                elif step.type == WorkflowStepType.JOIN:
                    resolved = self._validate_workflow_target_ref(
                        workflow_name,
                        step_name,
                        "next",
                        step.next,
                        workflow.steps,
                    )
                    if resolved is not None:
                        graph[step_name].append(resolved)

                elif step.type == WorkflowStepType.RETRY:
                    if (
                        not self._is_unresolved_var(step.objective)
                        and step.objective not in self._s.objectives
                    ):
                        self._err(
                            f"Workflow '{workflow_name}' step '{step_name}' "
                            f"references undefined objective '{step.objective}'"
                        )
                    for field_name, target in (
                        ("on-success", step.on_success),
                        ("on-exhausted", step.on_exhausted),
                    ):
                        resolved = self._validate_workflow_target_ref(
                            workflow_name,
                            step_name,
                            field_name,
                            target,
                            workflow.steps,
                        )
                        if resolved is not None:
                            graph[step_name].append(resolved)

                elif step.type == WorkflowStepType.END:
                    graph[step_name] = []

                if step_name not in graph:
                    graph[step_name] = []

            for join_step, sources in join_targets.items():
                if self._is_unresolved_var(join_step):
                    continue
                join_def = workflow.steps.get(join_step)
                if join_def is not None and join_def.type != WorkflowStepType.JOIN:
                    self._err(
                        f"Workflow '{workflow_name}' step '{join_step}' is used "
                        "as a parallel join but is not a join step"
                    )
                if len(sources) > 1:
                    self._err(
                        f"Workflow '{workflow_name}' join step '{join_step}' "
                        "may only be targeted by one parallel step"
                    )

            for step_name, step in workflow.steps.items():
                if step.type != WorkflowStepType.JOIN:
                    continue
                sources = join_targets.get(step_name, [])
                if not sources:
                    self._err(
                        f"Workflow '{workflow_name}' join step '{step_name}' "
                        "is not referenced by any parallel step"
                    )

            if graph and _topological_sort(graph) is None:
                self._err(
                    f"Workflow '{workflow_name}' graph contains a cycle"
                )

            if (
                self._is_unresolved_var(workflow.start)
                or workflow.start not in workflow.steps
            ):
                continue

            reachable: set[str] = set()
            stack = [workflow.start]
            while stack:
                current = stack.pop()
                if current in reachable:
                    continue
                reachable.add(current)
                stack.extend(graph.get(current, []))

            unreachable = sorted(set(workflow.steps) - reachable)
            if unreachable:
                self._err(
                    f"Workflow '{workflow_name}' contains unreachable steps: "
                    + ", ".join(unreachable)
                )

            predecessors: dict[str, set[str]] = {
                step_name: set() for step_name in reachable
            }
            for source, edges in graph.items():
                if source not in reachable:
                    continue
                for target in edges:
                    if target in reachable:
                        predecessors[target].add(source)

            for step_name, step in workflow.steps.items():
                if step.type != WorkflowStepType.PARALLEL:
                    continue
                if (
                    self._is_unresolved_var(step.join)
                    or step.join not in workflow.steps
                    or step.join not in reachable
                ):
                    continue
                allowed_predecessors = branch_closure(
                    graph,
                    branches=(
                        branch
                        for branch in step.branches
                        if branch in reachable and branch in workflow.steps
                    ),
                    join_step=step.join,
                )
                foreign_predecessors = sorted(
                    predecessor
                    for predecessor in predecessors.get(step.join, set())
                    if predecessor not in allowed_predecessors
                )
                if foreign_predecessors:
                    self._err(
                        f"Workflow '{workflow_name}' join step '{step.join}' "
                        "may only be entered from the owning parallel's branch "
                        "closure; unexpected predecessors: "
                        + ", ".join(foreign_predecessors)
                    )

            available_memo: dict[str, set[str]] = {}
            branch_memo: dict[tuple[str, str], set[str]] = {}

            for step_name, refs in predicate_step_refs.items():
                if step_name not in reachable:
                    continue
                available_before = self._available_step_state_before(
                    step_name,
                    workflow.steps,
                    graph,
                    predecessors,
                    workflow.start,
                    join_targets,
                    available_memo=available_memo,
                    branch_memo=branch_memo,
                    visiting=set(),
                )
                for ref_name in refs:
                    if self._is_unresolved_var(ref_name):
                        continue
                    if ref_name not in available_before:
                        self._err(
                            f"Workflow '{workflow_name}' step '{step_name}' "
                            f"references step state '{ref_name}' that is not "
                            "guaranteed to be known before this predicate"
                        )

            for step_name, step in workflow.steps.items():
                if step.type != WorkflowStepType.PARALLEL:
                    continue
                if (
                    self._is_unresolved_var(step.join)
                    or step.join not in workflow.steps
                ):
                    continue
                for branch_ref in step.branches:
                    if self._is_unresolved_var(branch_ref) or branch_ref not in workflow.steps:
                        continue
                    if not self._all_paths_reach_join(
                        branch_ref,
                        step.join,
                        graph,
                        memo={},
                        visiting=set(),
                    ):
                        self._err(
                            f"Workflow '{workflow_name}' parallel step "
                            f"'{step_name}' requires every explicit branch path "
                            f"from '{branch_ref}' to converge on join "
                            f"'{step.join}'"
                        )

    def _verify_variables(self) -> None:
        defined = set(self._s.variables.keys())

        def visit(value: object, path: str) -> None:
            if isinstance(value, BaseModel):
                for field_name in value.__class__.model_fields:
                    if isinstance(value, Scenario) and field_name == "variables":
                        continue
                    child = getattr(value, field_name)
                    child_path = f"{path}.{field_name}" if path else field_name
                    visit(child, child_path)
                return

            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    visit(child, child_path)
                return

            if isinstance(value, list):
                for index, child in enumerate(value):
                    child_path = f"{path}[{index}]"
                    visit(child, child_path)
                return

            if self._is_unresolved_var(value):
                variable_name = extract_variable_name(value)
                if variable_name and variable_name not in defined:
                    self._err(
                        f"Undefined variable '{variable_name}' referenced at "
                        f"'{path}'"
                    )

        visit(self._s, "")

    def _all_named_elements(self) -> set[str]:
        """Collect all named element keys across all scenario sections."""
        return set(self._named_ref_index().keys())

    def _all_targetable_elements(self) -> set[str]:
        """Collect named elements that can serve as objective targets."""
        return set(self._named_ref_index(targetable=True).keys())

    def _verify_features(self) -> None:
        # Check vulnerability references
        for name, feat in self._s.features.items():
            for vuln_name in feat.vulnerabilities:
                if self._is_unresolved_var(vuln_name):
                    continue
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
                if self._is_unresolved_var(dep):
                    continue
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
                if self._is_unresolved_var(cond):
                    continue
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
            unknown_max_score = False
            for metric_name in evaluation.metrics:
                if self._is_unresolved_var(metric_name):
                    unknown_max_score = True
                    continue
                if metric_name not in self._s.metrics:
                    self._err(
                        f"Evaluation '{name}' references undefined metric "
                        f"'{metric_name}'"
                    )
                else:
                    metric_max_score = self._s.metrics[metric_name].max_score
                    if isinstance(metric_max_score, int):
                        max_total += metric_max_score
                    else:
                        unknown_max_score = True

            if (
                isinstance(evaluation.min_score.absolute, int)
                and not unknown_max_score
            ):
                if evaluation.min_score.absolute > max_total:
                    self._err(
                        f"Evaluation '{name}' absolute min-score "
                        f"({evaluation.min_score.absolute}) exceeds sum of "
                        f"metric max-scores ({max_total})"
                    )

    def _verify_tlos(self) -> None:
        for name, tlo in self._s.tlos.items():
            if self._is_unresolved_var(tlo.evaluation):
                continue
            if tlo.evaluation not in self._s.evaluations:
                self._err(
                    f"TLO '{name}' references undefined evaluation "
                    f"'{tlo.evaluation}'"
                )

    def _verify_goals(self) -> None:
        for name, goal in self._s.goals.items():
            for tlo_name in goal.tlos:
                if self._is_unresolved_var(tlo_name):
                    continue
                if tlo_name not in self._s.tlos:
                    self._err(
                        f"Goal '{name}' references undefined TLO '{tlo_name}'"
                    )

    def _verify_entities(self) -> None:
        flat = flatten_entities(self._s.entities)

        def check_entity(name: str, entity: "Entity") -> None:
            for tlo_name in entity.tlos:
                if self._is_unresolved_var(tlo_name):
                    continue
                if tlo_name not in self._s.tlos:
                    self._err(
                        f"Entity '{name}' references undefined TLO '{tlo_name}'"
                    )
            for vuln_name in entity.vulnerabilities:
                if self._is_unresolved_var(vuln_name):
                    continue
                if vuln_name not in self._s.vulnerabilities:
                    self._err(
                        f"Entity '{name}' references undefined vulnerability "
                        f"'{vuln_name}'"
                    )
            for event_name in entity.events:
                if self._is_unresolved_var(event_name):
                    continue
                if event_name not in self._s.events:
                    self._err(
                        f"Entity '{name}' references undefined event "
                        f"'{event_name}'"
                    )

        for name, entity in flat.items():
            check_entity(name, entity)

    def _verify_injects(self) -> None:
        flat_names = self._all_entity_names()

        for name, inject in self._s.injects.items():
            if (
                inject.from_entity
                and not self._is_unresolved_var(inject.from_entity)
                and inject.from_entity not in flat_names
            ):
                self._err(
                    f"Inject '{name}' from_entity '{inject.from_entity}' "
                    f"is not a defined entity"
                )
            for to_name in inject.to_entities:
                if self._is_unresolved_var(to_name):
                    continue
                if to_name not in flat_names:
                    self._err(
                        f"Inject '{name}' to_entity '{to_name}' "
                        f"is not a defined entity"
                    )
            for tlo_name in inject.tlos:
                if self._is_unresolved_var(tlo_name):
                    continue
                if tlo_name not in self._s.tlos:
                    self._err(
                        f"Inject '{name}' references undefined TLO '{tlo_name}'"
                    )

    def _verify_events(self) -> None:
        for name, event in self._s.events.items():
            for cond_name in event.conditions:
                if self._is_unresolved_var(cond_name):
                    continue
                if cond_name not in self._s.conditions:
                    self._err(
                        f"Event '{name}' references undefined condition "
                        f"'{cond_name}'"
                    )
            for inj_name in event.injects:
                if self._is_unresolved_var(inj_name):
                    continue
                if inj_name not in self._s.injects:
                    self._err(
                        f"Event '{name}' references undefined inject '{inj_name}'"
                    )

    def _verify_scripts(self) -> None:
        for name, script in self._s.scripts.items():
            for event_name in script.events:
                if self._is_unresolved_var(event_name):
                    continue
                if event_name not in self._s.events:
                    self._err(
                        f"Script '{name}' references undefined event "
                        f"'{event_name}'"
                    )

    def _verify_stories(self) -> None:
        for name, story in self._s.stories.items():
            for script_name in story.scripts:
                if self._is_unresolved_var(script_name):
                    continue
                if script_name not in self._s.scripts:
                    self._err(
                        f"Story '{name}' references undefined script "
                        f"'{script_name}'"
                    )

    def _verify_roles(self) -> None:
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
