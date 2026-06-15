"""Validation passes for relationships, agents and objectives.

Enforces that relationships and objectives reference defined elements, that
agent knowledge/account/subnet references resolve, and that objective success
criteria, windows and dependency graphs are consistent.
"""

from aptl.core.sdl.agents import Agent
from aptl.core.sdl.objectives import Objective, ObjectiveWindow
from aptl.core.sdl.validator_base import _topological_sort
from aptl.core.sdl.validator_refs import _RefIndexMixin


class _ObjectiveMixin(_RefIndexMixin):
    """Relationship, agent and objective validation passes."""

    def _verify_relationships(self) -> None:
        """Validate relationship source/target references."""
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

    def _verify_agent_knowledge_hosts(self, name: str, agent: Agent) -> None:
        """Validate initial-knowledge host references point at VM nodes."""
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

    def _verify_agent_knowledge_subnets(self, name: str, agent: Agent) -> None:
        """Validate initial-knowledge subnet references point at switches."""
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

    def _verify_agent_knowledge_services(
        self, name: str, agent: Agent, service_names: set[str]
    ) -> None:
        """Validate initial-knowledge service references are known services."""
        for service_name in agent.initial_knowledge.services:
            if self._is_unresolved_var(service_name):
                continue
            if service_name not in service_names:
                self._err(
                    f"Agent '{name}' initial_knowledge service "
                    f"'{service_name}' not in node service names"
                )

    def _verify_agent_knowledge_accounts(self, name: str, agent: Agent) -> None:
        """Validate initial-knowledge account references are defined accounts."""
        for acct_name in agent.initial_knowledge.accounts:
            if self._is_unresolved_var(acct_name):
                continue
            if acct_name not in self._s.accounts:
                self._err(
                    f"Agent '{name}' initial_knowledge account "
                    f"'{acct_name}' not in accounts section"
                )

    def _verify_agent_initial_knowledge(
        self, name: str, agent: Agent, service_names: set[str]
    ) -> None:
        """Validate an agent's initial-knowledge host/subnet/service/account refs."""
        self._verify_agent_knowledge_hosts(name, agent)
        self._verify_agent_knowledge_subnets(name, agent)
        self._verify_agent_knowledge_services(name, agent, service_names)
        self._verify_agent_knowledge_accounts(name, agent)

    def _collect_service_names(self) -> set[str]:
        """Return the set of named service names across all nodes."""
        return {
            service.name
            for node in self._s.nodes.values()
            for service in node.services
            if service.name
        }

    def _verify_agent(
        self,
        name: str,
        agent: Agent,
        flat_entity_names: set[str],
        service_names: set[str],
    ) -> None:
        """Validate one agent's entity, account, subnet and knowledge refs."""
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
        self._verify_agent_allowed_subnets(name, agent)
        if agent.initial_knowledge:
            self._verify_agent_initial_knowledge(name, agent, service_names)

    def _verify_agent_allowed_subnets(self, name: str, agent: Agent) -> None:
        """Validate an agent's allowed-subnet references point at switches."""
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

    def _verify_agents(self) -> None:
        """Validate every agent's references."""
        flat_entity_names = self._all_entity_names()
        service_names = self._collect_service_names()
        for name, agent in self._s.agents.items():
            self._verify_agent(name, agent, flat_entity_names, service_names)

    def _verify_objective_actor(
        self, name: str, objective: Objective, actor_entities: set[str]
    ) -> None:
        """Validate an objective's agent/entity refs and declared actions."""
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

    def _verify_objective_success(self, name: str, objective: Objective) -> None:
        """Validate objective targets and success-criteria references."""
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

    def _verify_objective_window_scripts(
        self, name: str, window: ObjectiveWindow
    ) -> tuple[set[str], set[str]]:
        """Validate window story/script refs and their cross-consistency."""
        referenced_story_scripts: set[str] = set()
        referenced_scripts: set[str] = set()

        for story_name in window.stories:
            if self._is_unresolved_var(story_name):
                continue
            story = self._s.stories.get(story_name)
            if story is None:
                self._err(
                    f"Objective '{name}' references undefined story "
                    f"'{story_name}' in window"
                )
                continue
            referenced_story_scripts.update(story.scripts)

        for script_name in window.scripts:
            if self._is_unresolved_var(script_name):
                continue
            script = self._s.scripts.get(script_name)
            if script is None:
                self._err(
                    f"Objective '{name}' references undefined script "
                    f"'{script_name}' in window"
                )
                continue
            referenced_scripts.add(script_name)
            if (
                referenced_story_scripts
                and script_name not in referenced_story_scripts
            ):
                self._err(
                    f"Objective '{name}' window script '{script_name}' "
                    "is not included by the referenced stories"
                )

        return referenced_scripts, referenced_story_scripts

    def _verify_objective_window_events(
        self, name: str, window: ObjectiveWindow, candidate_scripts: set[str]
    ) -> None:
        """Validate window event refs against the candidate scripts' events."""
        candidate_events: set[str] = set()
        for script_name in candidate_scripts:
            script = self._s.scripts.get(script_name)
            if script is not None:
                candidate_events.update(script.events.keys())

        for event_name in window.events:
            if self._is_unresolved_var(event_name):
                continue
            if event_name not in self._s.events:
                self._err(
                    f"Objective '{name}' references undefined event "
                    f"'{event_name}' in window"
                )
                continue
            if candidate_events and event_name not in candidate_events:
                self._err(
                    f"Objective '{name}' window event '{event_name}' "
                    "is not included by the referenced scripts"
                )

    def _verify_objective_window_step(
        self,
        name: str,
        step_ref: str,
        referenced_workflows: set[str],
    ) -> None:
        """Validate a single ``<workflow>.<step>`` window step reference."""
        if "." not in step_ref:
            self._err(
                f"Objective '{name}' window step '{step_ref}' must "
                "use '<workflow>.<step>' syntax"
            )
            return

        workflow_name, step_name = step_ref.split(".", 1)
        workflow = self._s.workflows.get(workflow_name)
        if workflow is None:
            self._err(
                f"Objective '{name}' window step '{step_ref}' "
                f"references undefined workflow '{workflow_name}'"
            )
            return
        if referenced_workflows and workflow_name not in referenced_workflows:
            self._err(
                f"Objective '{name}' window step '{step_ref}' "
                "is not part of the referenced workflows"
            )
        if step_name not in workflow.steps:
            self._err(
                f"Objective '{name}' window step '{step_ref}' "
                f"references undefined step '{step_name}'"
            )

    def _verify_objective_window_steps(
        self, name: str, window: ObjectiveWindow, referenced_workflows: set[str]
    ) -> None:
        """Validate every window step reference and the workflow precondition."""
        if window.steps and not window.workflows:
            self._err(
                f"Objective '{name}' window steps require at least one "
                "referenced workflow"
            )

        for step_ref in window.steps:
            if self._is_unresolved_var(step_ref):
                continue
            self._verify_objective_window_step(
                name, step_ref, referenced_workflows
            )

    def _resolve_window_workflows(
        self, name: str, window: ObjectiveWindow
    ) -> set[str]:
        """Validate window workflow refs and return the resolved set."""
        referenced_workflows: set[str] = set()
        for workflow_name in window.workflows:
            if self._is_unresolved_var(workflow_name):
                continue
            workflow = self._s.workflows.get(workflow_name)
            if workflow is None:
                self._err(
                    f"Objective '{name}' references undefined workflow "
                    f"'{workflow_name}' in window"
                )
                continue
            referenced_workflows.add(workflow_name)
        return referenced_workflows

    def _verify_objective_window(
        self, name: str, window: ObjectiveWindow
    ) -> None:
        """Validate an objective window's scripts, events, workflows and steps."""
        referenced_scripts, referenced_story_scripts = (
            self._verify_objective_window_scripts(name, window)
        )

        candidate_scripts = referenced_scripts or referenced_story_scripts
        self._verify_objective_window_events(name, window, candidate_scripts)

        referenced_workflows = self._resolve_window_workflows(name, window)
        self._verify_objective_window_steps(name, window, referenced_workflows)

    def _verify_objective(
        self, name: str, objective: Objective, actor_entities: set[str]
    ) -> None:
        """Validate a single objective's actor, success, window and deps."""
        self._verify_objective_actor(name, objective, actor_entities)
        self._verify_objective_success(name, objective)

        if objective.window:
            self._verify_objective_window(name, objective.window)

        for dep_name in objective.depends_on:
            if self._is_unresolved_var(dep_name):
                continue
            if dep_name not in self._s.objectives:
                self._err(
                    f"Objective '{name}' depends on undefined objective "
                    f"'{dep_name}'"
                )

    def _verify_objectives(self) -> None:
        """Validate every objective and its dependency-graph acyclicity."""
        actor_entities = self._all_entity_names()

        for name, objective in self._s.objectives.items():
            self._verify_objective(name, objective, actor_entities)

        dep_graph: dict[str, list[str]] = {}
        for name, objective in self._s.objectives.items():
            dep_graph[name] = [
                dep for dep in objective.depends_on
                if not self._is_unresolved_var(dep) and dep in self._s.objectives
            ]
        if dep_graph and _topological_sort(dep_graph) is None:
            self._err("Objective dependency graph contains a cycle")
