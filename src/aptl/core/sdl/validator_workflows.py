"""Validation passes for workflows and their step graphs.

Validates predicate references, per-step-type edge wiring (objective, if,
parallel, while, on-error), step-name constraints, cycle detection, and
reachability from each workflow's start step.
"""

from aptl.core.sdl.orchestration import (
    Workflow,
    WorkflowPredicate,
    WorkflowStep,
    WorkflowStepType,
)
from aptl.core.sdl.validator_base import _topological_sort
from aptl.core.sdl.validator_base import _ValidatorCore


class _WorkflowMixin(_ValidatorCore):
    """Workflow and workflow-step validation passes."""

    def _validate_workflow_predicate(
        self,
        workflow_name: str,
        step_name: str,
        predicate: WorkflowPredicate,
        workflow_steps: dict[str, WorkflowStep],
    ) -> None:
        """Validate all references within a workflow predicate."""
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
        for outcome_ref in predicate.step_outcomes:
            if self._is_unresolved_var(outcome_ref):
                continue
            if outcome_ref not in workflow_steps:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"references undefined step outcome "
                    f"'{outcome_ref}' in predicate"
                )

    def _verify_next_edge(
        self,
        workflow_name: str,
        step_name: str,
        next_ref: str,
        workflow: Workflow,
        edge_label: str,
    ) -> list[str]:
        """Validate a ``next``-style edge and return it when it is a real step."""
        if not next_ref or self._is_unresolved_var(next_ref):
            return []
        if next_ref not in workflow.steps:
            self._err(
                f"Workflow '{workflow_name}' step '{step_name}' "
                f"{edge_label} '{next_ref}' is not defined"
            )
            return []
        return [next_ref]

    def _verify_workflow_objective_step(
        self,
        workflow_name: str,
        step_name: str,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> list[str]:
        """Validate an OBJECTIVE step's objective ref and next edge."""
        if (
            not self._is_unresolved_var(step.objective)
            and step.objective not in self._s.objectives
        ):
            self._err(
                f"Workflow '{workflow_name}' step '{step_name}' "
                f"references undefined objective '{step.objective}'"
            )
        return self._verify_next_edge(
            workflow_name, step_name, step.next, workflow, "next step"
        )

    def _verify_workflow_if_step(
        self,
        workflow_name: str,
        step_name: str,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> list[str]:
        """Validate an IF step's predicate and then/else branch edges."""
        edges: list[str] = []
        self._validate_workflow_predicate(
            workflow_name, step_name, step.when, workflow.steps,
        )

        for branch_label, branch_ref in (
            ("then", step.then_step),
            ("else", step.else_step),
        ):
            if self._is_unresolved_var(branch_ref):
                continue
            if branch_ref not in workflow.steps:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"{branch_label} step '{branch_ref}' is not "
                    "defined"
                )
                continue
            edges.append(branch_ref)
        return edges

    def _verify_workflow_parallel_step(
        self,
        workflow_name: str,
        step_name: str,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> list[str]:
        """Validate a PARALLEL step's branch edges and join edge."""
        edges: list[str] = []
        for branch_ref in step.branches:
            if self._is_unresolved_var(branch_ref):
                continue
            if branch_ref not in workflow.steps:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"branch '{branch_ref}' is not defined"
                )
                continue
            edges.append(branch_ref)

        edges.extend(
            self._verify_next_edge(
                workflow_name, step_name, step.next, workflow, "join step"
            )
        )
        return edges

    def _verify_workflow_while_step(
        self,
        workflow_name: str,
        step_name: str,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> list[str]:
        """Validate a WHILE step's predicate, body edge and next edge."""
        edges: list[str] = []
        self._validate_workflow_predicate(
            workflow_name, step_name, step.when, workflow.steps,
        )

        if not self._is_unresolved_var(step.body):
            if step.body not in workflow.steps:
                self._err(
                    f"Workflow '{workflow_name}' step '{step_name}' "
                    f"body step '{step.body}' is not defined"
                )
            else:
                edges.append(step.body)

        edges.extend(
            self._verify_next_edge(
                workflow_name, step_name, step.next, workflow, "next step"
            )
        )
        return edges

    def _verify_workflow_on_error(
        self,
        workflow_name: str,
        step_name: str,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> list[str]:
        """Validate a step's on-error edge for applicable step types."""
        edges: list[str] = []
        if not step.on_error or self._is_unresolved_var(step.on_error):
            return edges
        if step.on_error == step_name:
            self._err(
                f"Workflow '{workflow_name}' step '{step_name}' "
                f"on-error cannot reference itself"
            )
        elif step.on_error not in workflow.steps:
            self._err(
                f"Workflow '{workflow_name}' step '{step_name}' "
                f"on-error step '{step.on_error}' is not defined"
            )
        else:
            edges.append(step.on_error)
        return edges

    _STEP_EDGE_VERIFIERS = {
        WorkflowStepType.OBJECTIVE: _verify_workflow_objective_step,
        WorkflowStepType.IF: _verify_workflow_if_step,
        WorkflowStepType.PARALLEL: _verify_workflow_parallel_step,
        WorkflowStepType.WHILE: _verify_workflow_while_step,
    }

    def _verify_workflow_step(
        self,
        workflow_name: str,
        step_name: str,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> list[str]:
        """Validate a single workflow step and return its outgoing edges."""
        if "." in step_name:
            self._err(
                f"Workflow '{workflow_name}' step '{step_name}' cannot "
                "contain '.' because objective windows use "
                "'<workflow>.<step>' syntax"
            )

        verifier = self._STEP_EDGE_VERIFIERS.get(step.type)
        if verifier is not None:
            edges = verifier(self, workflow_name, step_name, step, workflow)
        else:
            edges = []

        edges.extend(
            self._verify_workflow_on_error(
                workflow_name, step_name, step, workflow
            )
        )
        return edges

    def _verify_workflow_reachability(
        self, workflow_name: str, workflow: Workflow, graph: dict[str, list[str]]
    ) -> None:
        """Report steps unreachable from the workflow's start step."""
        if (
            self._is_unresolved_var(workflow.start)
            or workflow.start not in workflow.steps
        ):
            return

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

    def _verify_workflow(self, workflow_name: str, workflow: Workflow) -> None:
        """Validate one workflow's name, start, step graph and reachability."""
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
        for step_name, step in workflow.steps.items():
            graph[step_name] = self._verify_workflow_step(
                workflow_name, step_name, step, workflow
            )

        if graph and _topological_sort(graph) is None:
            self._err(f"Workflow '{workflow_name}' graph contains a cycle")

        self._verify_workflow_reachability(workflow_name, workflow, graph)

    def _verify_workflows(self) -> None:
        """Validate every workflow in the scenario."""
        for workflow_name, workflow in self._s.workflows.items():
            self._verify_workflow(workflow_name, workflow)
