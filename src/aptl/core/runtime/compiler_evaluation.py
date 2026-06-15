"""Evaluation-domain builders for the SDL-to-runtime compiler.

Builds condition bindings, metrics, evaluations, TLOs, goals, and objectives,
resolving the references that wire the evaluation graph together.
"""

from aptl.core.runtime.compiler_addresses import (
    _condition_binding_address,
    _dedupe,
    _dump,
    _evaluation_address,
    _event_address,
    _goal_address,
    _metric_address,
    _node_address,
    _objective_address,
    _script_address,
    _story_address,
    _tlo_address,
    _workflow_address,
)
from aptl.core.runtime.compiler_resolvers import (
    _resolve_binding_ref,
    _resolve_binding_refs,
    _resolve_named_refs,
    _resolve_workflow_step_refs,
)
from aptl.core.runtime.models import (
    ConditionBinding,
    Diagnostic,
    EvaluationRuntime,
    GoalRuntime,
    MetricRuntime,
    ObjectiveRuntime,
    RuntimeTemplate,
    TLORuntime,
)
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.objectives import Objective
from aptl.core.sdl.scenario import Scenario


def _build_condition_bindings(
    scenario: Scenario,
    condition_templates: dict[str, RuntimeTemplate],
) -> tuple[dict[str, ConditionBinding], list[Diagnostic]]:
    """Bind declared node conditions to their condition templates."""
    condition_bindings: dict[str, ConditionBinding] = {}
    diagnostics: list[Diagnostic] = []
    for node_name, node in scenario.nodes.items():
        if node.type != NodeType.VM:
            continue
        node_addr = _node_address(node_name)
        for condition_name, role_name in node.conditions.items():
            template = condition_templates.get(condition_name)
            if template is None:
                diagnostics.append(
                    Diagnostic(
                        code="evaluation.condition-template-ref-unbound",
                        domain="evaluation",
                        address=node_addr,
                        message=(
                            f"Condition binding '{condition_name}' on node '{node_name}' "
                            "does not resolve to a declared condition template."
                        ),
                    )
                )
                continue
            address = _condition_binding_address(node_name, condition_name)
            condition_bindings[address] = ConditionBinding(
                address=address,
                name=condition_name,
                node_name=node_name,
                node_address=node_addr,
                condition_name=condition_name,
                template_address=template.address,
                role_name=role_name,
                refresh_dependencies=(node_addr,),
                spec={
                    "binding": {
                        "node": node_name,
                        "role": role_name,
                    },
                    "template": template.spec,
                },
            )
    return condition_bindings, diagnostics


def _build_metrics(
    scenario: Scenario,
    condition_bindings: dict[str, ConditionBinding],
) -> tuple[dict[str, MetricRuntime], list[Diagnostic]]:
    """Build metric resources, binding each to its condition where present."""
    metrics: dict[str, MetricRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, metric in scenario.metrics.items():
        metric_spec = _dump(metric)
        metric_address = _metric_address(name)
        condition_name = metric_spec.get("condition") or ""
        condition_addresses: tuple[str, ...] = ()
        if condition_name:
            condition_addresses, metric_diagnostics = _resolve_binding_ref(
                condition_bindings,
                ref_name=condition_name,
                owner_address=metric_address,
                domain="evaluation",
                code_prefix="evaluation.condition-ref",
                binding_attr="condition_name",
                binding_label="condition",
            )
            diagnostics.extend(metric_diagnostics)
        metrics[metric_address] = MetricRuntime(
            address=metric_address,
            name=name,
            condition_name=condition_name,
            condition_addresses=condition_addresses,
            ordering_dependencies=condition_addresses,
            refresh_dependencies=condition_addresses,
            spec=metric_spec,
        )
    return metrics, diagnostics


def _build_evaluations(
    scenario: Scenario,
) -> tuple[dict[str, EvaluationRuntime], list[Diagnostic]]:
    """Build evaluation resources from their referenced metrics."""
    evaluations: dict[str, EvaluationRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, evaluation in scenario.evaluations.items():
        evaluation_address = _evaluation_address(name)
        metric_addresses, evaluation_diagnostics = _resolve_named_refs(
            ref_names=list(evaluation.metrics),
            available_names=set(scenario.metrics),
            address_builder=_metric_address,
            owner_address=evaluation_address,
            domain="evaluation",
            code_prefix="evaluation.metric-ref",
            resource_label="metric",
        )
        diagnostics.extend(evaluation_diagnostics)
        evaluations[evaluation_address] = EvaluationRuntime(
            address=evaluation_address,
            name=name,
            metric_addresses=metric_addresses,
            ordering_dependencies=metric_addresses,
            refresh_dependencies=metric_addresses,
            spec=_dump(evaluation),
        )
    return evaluations, diagnostics


def _build_tlos(
    scenario: Scenario,
) -> tuple[dict[str, TLORuntime], list[Diagnostic]]:
    """Build TLO resources from their referenced evaluations."""
    tlos: dict[str, TLORuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, tlo in scenario.tlos.items():
        tlo_address = _tlo_address(name)
        evaluation_addresses, tlo_diagnostics = _resolve_named_refs(
            ref_names=[tlo.evaluation],
            available_names=set(scenario.evaluations),
            address_builder=_evaluation_address,
            owner_address=tlo_address,
            domain="evaluation",
            code_prefix="evaluation.evaluation-ref",
            resource_label="evaluation",
        )
        diagnostics.extend(tlo_diagnostics)
        evaluation_address = evaluation_addresses[0] if evaluation_addresses else ""
        tlos[tlo_address] = TLORuntime(
            address=tlo_address,
            name=name,
            evaluation_address=evaluation_address,
            ordering_dependencies=evaluation_addresses,
            refresh_dependencies=evaluation_addresses,
            spec=_dump(tlo),
        )
    return tlos, diagnostics


def _build_goals(
    scenario: Scenario,
) -> tuple[dict[str, GoalRuntime], list[Diagnostic]]:
    """Build goal resources from their referenced TLOs."""
    goals: dict[str, GoalRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, goal in scenario.goals.items():
        goal_address = _goal_address(name)
        tlo_addresses, goal_diagnostics = _resolve_named_refs(
            ref_names=list(goal.tlos),
            available_names=set(scenario.tlos),
            address_builder=_tlo_address,
            owner_address=goal_address,
            domain="evaluation",
            code_prefix="evaluation.tlo-ref",
            resource_label="TLO",
        )
        diagnostics.extend(goal_diagnostics)
        goals[goal_address] = GoalRuntime(
            address=goal_address,
            name=name,
            tlo_addresses=tlo_addresses,
            ordering_dependencies=tlo_addresses,
            refresh_dependencies=tlo_addresses,
            spec=_dump(goal),
        )
    return goals, diagnostics


def _resolve_objective_window(
    scenario: Scenario,
    objective: Objective,
    objective_address: str,
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    list[Diagnostic],
]:
    """Resolve the optional success window references for an objective."""
    window_story_addresses: tuple[str, ...] = ()
    window_script_addresses: tuple[str, ...] = ()
    window_event_addresses: tuple[str, ...] = ()
    window_workflow_addresses: tuple[str, ...] = ()
    window_step_refs: tuple[str, ...] = ()
    window_step_workflow_addresses: tuple[str, ...] = ()
    diagnostics: list[Diagnostic] = []
    if objective.window is not None:
        window_story_addresses, story_diagnostics = _resolve_named_refs(
            ref_names=list(objective.window.stories),
            available_names=set(scenario.stories),
            address_builder=_story_address,
            owner_address=objective_address,
            domain="evaluation",
            code_prefix="evaluation.story-ref",
            resource_label="story",
        )
        window_script_addresses, script_diagnostics = _resolve_named_refs(
            ref_names=list(objective.window.scripts),
            available_names=set(scenario.scripts),
            address_builder=_script_address,
            owner_address=objective_address,
            domain="evaluation",
            code_prefix="evaluation.script-ref",
            resource_label="script",
        )
        window_event_addresses, event_diagnostics = _resolve_named_refs(
            ref_names=list(objective.window.events),
            available_names=set(scenario.events),
            address_builder=_event_address,
            owner_address=objective_address,
            domain="evaluation",
            code_prefix="evaluation.event-ref",
            resource_label="event",
        )
        window_workflow_addresses, workflow_diagnostics = _resolve_named_refs(
            ref_names=list(objective.window.workflows),
            available_names=set(scenario.workflows),
            address_builder=_workflow_address,
            owner_address=objective_address,
            domain="evaluation",
            code_prefix="evaluation.workflow-ref",
            resource_label="workflow",
        )
        window_step_refs, window_step_workflow_addresses, step_diagnostics = (
            _resolve_workflow_step_refs(
                scenario,
                step_refs=list(objective.window.steps),
                owner_address=objective_address,
                domain="evaluation",
                code_prefix="evaluation.workflow-step-ref",
            )
        )
        diagnostics.extend(story_diagnostics)
        diagnostics.extend(script_diagnostics)
        diagnostics.extend(event_diagnostics)
        diagnostics.extend(workflow_diagnostics)
        diagnostics.extend(step_diagnostics)

    return (
        window_story_addresses,
        window_script_addresses,
        window_event_addresses,
        window_workflow_addresses,
        window_step_refs,
        window_step_workflow_addresses,
        diagnostics,
    )


def _resolve_objective_success_refs(
    scenario: Scenario,
    condition_bindings: dict[str, ConditionBinding],
    objective: Objective,
    objective_address: str,
) -> tuple[list[str], list[Diagnostic]]:
    """Resolve the success criteria references for an objective."""
    success_addresses: list[str] = []
    diagnostics: list[Diagnostic] = []
    condition_addresses, objective_diagnostics = _resolve_binding_refs(
        condition_bindings,
        ref_names=list(objective.success.conditions),
        owner_address=objective_address,
        domain="evaluation",
        code_prefix="evaluation.condition-ref",
        binding_attr="condition_name",
        binding_label="condition",
    )
    diagnostics.extend(objective_diagnostics)
    success_addresses.extend(condition_addresses)
    metric_addresses, metric_diagnostics = _resolve_named_refs(
        ref_names=list(objective.success.metrics),
        available_names=set(scenario.metrics),
        address_builder=_metric_address,
        owner_address=objective_address,
        domain="evaluation",
        code_prefix="evaluation.metric-ref",
        resource_label="metric",
    )
    evaluation_addresses, evaluation_diagnostics = _resolve_named_refs(
        ref_names=list(objective.success.evaluations),
        available_names=set(scenario.evaluations),
        address_builder=_evaluation_address,
        owner_address=objective_address,
        domain="evaluation",
        code_prefix="evaluation.evaluation-ref",
        resource_label="evaluation",
    )
    tlo_addresses, tlo_diagnostics = _resolve_named_refs(
        ref_names=list(objective.success.tlos),
        available_names=set(scenario.tlos),
        address_builder=_tlo_address,
        owner_address=objective_address,
        domain="evaluation",
        code_prefix="evaluation.tlo-ref",
        resource_label="TLO",
    )
    goal_addresses, goal_diagnostics = _resolve_named_refs(
        ref_names=list(objective.success.goals),
        available_names=set(scenario.goals),
        address_builder=_goal_address,
        owner_address=objective_address,
        domain="evaluation",
        code_prefix="evaluation.goal-ref",
        resource_label="goal",
    )
    diagnostics.extend(metric_diagnostics)
    diagnostics.extend(evaluation_diagnostics)
    diagnostics.extend(tlo_diagnostics)
    diagnostics.extend(goal_diagnostics)
    success_addresses.extend(metric_addresses)
    success_addresses.extend(evaluation_addresses)
    success_addresses.extend(tlo_addresses)
    success_addresses.extend(goal_addresses)
    return success_addresses, diagnostics


def _build_objectives(
    scenario: Scenario,
    condition_bindings: dict[str, ConditionBinding],
) -> tuple[dict[str, ObjectiveRuntime], list[Diagnostic]]:
    """Build objective resources, resolving success criteria and windows."""
    objectives: dict[str, ObjectiveRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, objective in scenario.objectives.items():
        objective_address = _objective_address(name)
        success_addresses, success_diagnostics = _resolve_objective_success_refs(
            scenario,
            condition_bindings,
            objective,
            objective_address,
        )
        diagnostics.extend(success_diagnostics)
        objective_dependencies, objective_dependency_diagnostics = _resolve_named_refs(
            ref_names=list(objective.depends_on),
            available_names=set(scenario.objectives),
            address_builder=_objective_address,
            owner_address=objective_address,
            domain="evaluation",
            code_prefix="evaluation.objective-ref",
            resource_label="objective",
        )
        diagnostics.extend(objective_dependency_diagnostics)

        (
            window_story_addresses,
            window_script_addresses,
            window_event_addresses,
            window_workflow_addresses,
            window_step_refs,
            window_step_workflow_addresses,
            window_diagnostics,
        ) = _resolve_objective_window(scenario, objective, objective_address)
        diagnostics.extend(window_diagnostics)

        actor_type = "agent" if objective.agent else "entity"
        actor_name = objective.agent or objective.entity
        ordering_dependencies = _dedupe([*success_addresses, *objective_dependencies])
        refresh_dependencies = _dedupe(
            [
                *success_addresses,
                *objective_dependencies,
                *window_story_addresses,
                *window_script_addresses,
                *window_event_addresses,
                *window_workflow_addresses,
                *window_step_workflow_addresses,
            ]
        )
        objectives[objective_address] = ObjectiveRuntime(
            address=objective_address,
            name=name,
            actor_type=actor_type,
            actor_name=actor_name,
            success_addresses=tuple(success_addresses),
            objective_dependencies=objective_dependencies,
            window_story_addresses=window_story_addresses,
            window_script_addresses=window_script_addresses,
            window_event_addresses=window_event_addresses,
            window_workflow_addresses=window_workflow_addresses,
            window_step_refs=window_step_refs,
            window_step_workflow_addresses=window_step_workflow_addresses,
            ordering_dependencies=ordering_dependencies,
            refresh_dependencies=refresh_dependencies,
            spec=_dump(objective),
        )
    return objectives, diagnostics
