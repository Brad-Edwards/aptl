"""Orchestration-domain builders for the SDL-to-runtime compiler.

Builds inject bindings, events, scripts, stories, and workflows, resolving the
references that connect the orchestration graph.
"""

from aptl.core.runtime.compiler_addresses import (
    _address,
    _dedupe,
    _dump,
    _evaluation_address,
    _event_address,
    _goal_address,
    _inject_address,
    _inject_binding_address,
    _metric_address,
    _node_address,
    _objective_address,
    _script_address,
    _story_address,
    _tlo_address,
    _workflow_address,
)
from aptl.core.runtime.compiler_resolvers import (
    _resolve_binding_refs,
    _resolve_named_refs,
    _resolve_resource_refs,
)
from aptl.core.runtime.models import (
    ConditionBinding,
    Diagnostic,
    EventRuntime,
    InjectBinding,
    InjectRuntime,
    RuntimeTemplate,
    ScriptRuntime,
    StoryRuntime,
    WorkflowRuntime,
)
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.orchestration import WorkflowStep
from aptl.core.sdl.scenario import Scenario


def _build_inject_bindings(
    scenario: Scenario,
    inject_templates: dict[str, RuntimeTemplate],
) -> tuple[dict[str, InjectBinding], list[Diagnostic]]:
    """Bind declared node injects to their inject templates."""
    inject_bindings: dict[str, InjectBinding] = {}
    diagnostics: list[Diagnostic] = []
    for node_name, node in scenario.nodes.items():
        if node.type != NodeType.VM:
            continue
        node_addr = _node_address(node_name)
        for inject_name, role_name in node.injects.items():
            template = inject_templates.get(inject_name)
            if template is None:
                diagnostics.append(
                    Diagnostic(
                        code="orchestration.inject-template-ref-unbound",
                        domain="orchestration",
                        address=node_addr,
                        message=(
                            f"Inject binding '{inject_name}' on node '{node_name}' "
                            "does not resolve to a declared inject template."
                        ),
                    )
                )
                continue
            inject_address = _inject_address(inject_name)
            address = _inject_binding_address(node_name, inject_name)
            inject_bindings[address] = InjectBinding(
                address=address,
                name=inject_name,
                node_name=node_name,
                node_address=node_addr,
                inject_name=inject_name,
                template_address=template.address,
                role_name=role_name,
                ordering_dependencies=(inject_address,),
                refresh_dependencies=(node_addr, inject_address),
                spec={
                    "binding": {
                        "node": node_name,
                        "role": role_name,
                    },
                    "inject_address": inject_address,
                },
            )
    return inject_bindings, diagnostics


def _build_events(
    scenario: Scenario,
    condition_bindings: dict[str, ConditionBinding],
    injects: dict[str, InjectRuntime],
    inject_bindings: dict[str, InjectBinding],
) -> tuple[dict[str, EventRuntime], list[Diagnostic]]:
    """Build event resources, resolving condition and inject references."""
    events: dict[str, EventRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, event in scenario.events.items():
        event_address = _event_address(name)
        condition_names = list(event.conditions)
        inject_names = list(event.injects)
        condition_addresses, condition_diagnostics = _resolve_binding_refs(
            condition_bindings,
            ref_names=condition_names,
            owner_address=event_address,
            domain="orchestration",
            code_prefix="orchestration.condition-ref",
            binding_attr="condition_name",
            binding_label="condition",
        )
        inject_addresses, inject_diagnostics = _resolve_resource_refs(
            injects,
            ref_names=inject_names,
            owner_address=event_address,
            domain="orchestration",
            code_prefix="orchestration.inject-ref",
            resource_label="inject",
        )
        diagnostics.extend(condition_diagnostics)
        diagnostics.extend(inject_diagnostics)
        inject_binding_ordering_dependencies = [
            address
            for address, binding in inject_bindings.items()
            if binding.inject_name in inject_names
        ]
        ordering_dependencies = _dedupe(
            [*inject_addresses, *inject_binding_ordering_dependencies]
        )
        refresh_dependencies = _dedupe(
            [
                *condition_addresses,
                *inject_addresses,
                *inject_binding_ordering_dependencies,
            ]
        )
        events[event_address] = EventRuntime(
            address=event_address,
            name=name,
            condition_names=tuple(condition_names),
            condition_addresses=condition_addresses,
            inject_names=tuple(inject_names),
            inject_addresses=inject_addresses,
            ordering_dependencies=ordering_dependencies,
            refresh_dependencies=refresh_dependencies,
            spec=_dump(event),
        )
    return events, diagnostics


def _build_scripts(
    scenario: Scenario,
) -> tuple[dict[str, ScriptRuntime], list[Diagnostic]]:
    """Build script resources from their referenced events."""
    scripts: dict[str, ScriptRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, script in scenario.scripts.items():
        script_address = _script_address(name)
        event_addresses, script_diagnostics = _resolve_named_refs(
            ref_names=list(script.events),
            available_names=set(scenario.events),
            address_builder=_event_address,
            owner_address=script_address,
            domain="orchestration",
            code_prefix="orchestration.event-ref",
            resource_label="event",
        )
        diagnostics.extend(script_diagnostics)
        scripts[script_address] = ScriptRuntime(
            address=script_address,
            name=name,
            event_addresses=event_addresses,
            ordering_dependencies=event_addresses,
            refresh_dependencies=event_addresses,
            spec=_dump(script),
        )
    return scripts, diagnostics


def _build_stories(
    scenario: Scenario,
) -> tuple[dict[str, StoryRuntime], list[Diagnostic]]:
    """Build story resources from their referenced scripts."""
    stories: dict[str, StoryRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, story in scenario.stories.items():
        story_address = _story_address(name)
        script_addresses, story_diagnostics = _resolve_named_refs(
            ref_names=list(story.scripts),
            available_names=set(scenario.scripts),
            address_builder=_script_address,
            owner_address=story_address,
            domain="orchestration",
            code_prefix="orchestration.script-ref",
            resource_label="script",
        )
        diagnostics.extend(story_diagnostics)
        stories[story_address] = StoryRuntime(
            address=story_address,
            name=name,
            script_addresses=script_addresses,
            ordering_dependencies=script_addresses,
            refresh_dependencies=script_addresses,
            spec=_dump(story),
        )
    return stories, diagnostics


def _resolve_workflow_step_predicate(
    scenario: Scenario,
    condition_bindings: dict[str, ConditionBinding],
    step: WorkflowStep,
    predicate_address: str,
) -> tuple[tuple[str, ...], list[str], list[str], list[Diagnostic]]:
    """Resolve a workflow step's ``when`` predicate references."""
    diagnostics: list[Diagnostic] = []
    condition_addresses, workflow_diagnostics = _resolve_binding_refs(
        condition_bindings,
        ref_names=list(step.when.conditions),
        owner_address=predicate_address,
        domain="orchestration",
        code_prefix="orchestration.condition-ref",
        binding_attr="condition_name",
        binding_label="condition",
    )
    diagnostics.extend(workflow_diagnostics)

    predicate_addresses: list[str] = list(condition_addresses)
    metric_addresses, metric_diagnostics = _resolve_named_refs(
        ref_names=list(step.when.metrics),
        available_names=set(scenario.metrics),
        address_builder=_metric_address,
        owner_address=predicate_address,
        domain="orchestration",
        code_prefix="orchestration.metric-ref",
        resource_label="metric",
    )
    evaluation_addresses, evaluation_diagnostics = _resolve_named_refs(
        ref_names=list(step.when.evaluations),
        available_names=set(scenario.evaluations),
        address_builder=_evaluation_address,
        owner_address=predicate_address,
        domain="orchestration",
        code_prefix="orchestration.evaluation-ref",
        resource_label="evaluation",
    )
    tlo_addresses, tlo_diagnostics = _resolve_named_refs(
        ref_names=list(step.when.tlos),
        available_names=set(scenario.tlos),
        address_builder=_tlo_address,
        owner_address=predicate_address,
        domain="orchestration",
        code_prefix="orchestration.tlo-ref",
        resource_label="TLO",
    )
    goal_addresses, goal_diagnostics = _resolve_named_refs(
        ref_names=list(step.when.goals),
        available_names=set(scenario.goals),
        address_builder=_goal_address,
        owner_address=predicate_address,
        domain="orchestration",
        code_prefix="orchestration.goal-ref",
        resource_label="goal",
    )
    predicate_objectives, objective_diagnostics = _resolve_named_refs(
        ref_names=list(step.when.objectives),
        available_names=set(scenario.objectives),
        address_builder=_objective_address,
        owner_address=predicate_address,
        domain="orchestration",
        code_prefix="orchestration.objective-ref",
        resource_label="objective",
    )
    diagnostics.extend(metric_diagnostics)
    diagnostics.extend(evaluation_diagnostics)
    diagnostics.extend(tlo_diagnostics)
    diagnostics.extend(goal_diagnostics)
    diagnostics.extend(objective_diagnostics)
    predicate_addresses.extend(metric_addresses)
    predicate_addresses.extend(evaluation_addresses)
    predicate_addresses.extend(tlo_addresses)
    predicate_addresses.extend(goal_addresses)
    predicate_addresses.extend(predicate_objectives)
    return (
        condition_addresses,
        predicate_addresses,
        list(predicate_objectives),
        diagnostics,
    )


def _build_workflow_step_edges(step: WorkflowStep) -> tuple[str, ...]:
    """Collect the outgoing graph edges declared by a workflow step."""
    edges: list[str] = []
    if step.next:
        edges.append(step.next)
    if step.then_step:
        edges.append(step.then_step)
    if step.else_step:
        edges.append(step.else_step)
    if step.body:
        edges.append(step.body)
    if step.on_error:
        edges.append(step.on_error)
    edges.extend(step.branches)
    return _dedupe(edges)


def _resolve_workflow_step_objective(
    scenario: Scenario,
    step: WorkflowStep,
    workflow_address: str,
) -> tuple[list[str], list[Diagnostic]]:
    """Resolve the objective reference declared directly on a workflow step."""
    objective_addresses, objective_diagnostics = _resolve_named_refs(
        ref_names=[step.objective],
        available_names=set(scenario.objectives),
        address_builder=_objective_address,
        owner_address=workflow_address,
        domain="orchestration",
        code_prefix="orchestration.objective-ref",
        resource_label="objective",
    )
    return list(objective_addresses), objective_diagnostics


def _build_workflows(
    scenario: Scenario,
    condition_bindings: dict[str, ConditionBinding],
) -> tuple[dict[str, WorkflowRuntime], list[Diagnostic]]:
    """Build workflow resources, resolving step graphs and predicates."""
    workflows: dict[str, WorkflowRuntime] = {}
    diagnostics: list[Diagnostic] = []
    for name, workflow in scenario.workflows.items():
        workflow_address = _workflow_address(name)
        step_graph: dict[str, tuple[str, ...]] = {}
        referenced_objectives: list[str] = []
        step_condition_addresses: dict[str, tuple[str, ...]] = {}
        step_predicate_addresses: dict[str, tuple[str, ...]] = {}

        for step_name, step in workflow.steps.items():
            step_graph[step_name] = _build_workflow_step_edges(step)

            if step.objective:
                objective_addresses, objective_diagnostics = (
                    _resolve_workflow_step_objective(scenario, step, workflow_address)
                )
                diagnostics.extend(objective_diagnostics)
                referenced_objectives.extend(objective_addresses)

            if step.when is None:
                continue

            predicate_address = _address(workflow_address, "step", step_name)
            (
                condition_addresses,
                predicate_addresses,
                predicate_objectives,
                predicate_diagnostics,
            ) = _resolve_workflow_step_predicate(
                scenario,
                condition_bindings,
                step,
                predicate_address,
            )
            diagnostics.extend(predicate_diagnostics)
            referenced_objectives.extend(predicate_objectives)

            step_condition_addresses[step_name] = condition_addresses
            step_predicate_addresses[step_name] = _dedupe(predicate_addresses)

        objective_addresses = _dedupe(referenced_objectives)
        predicate_dependency_addresses = _dedupe(
            [
                address
                for addresses in step_predicate_addresses.values()
                for address in addresses
            ]
        )
        workflows[workflow_address] = WorkflowRuntime(
            address=workflow_address,
            name=name,
            referenced_objective_addresses=objective_addresses,
            step_condition_addresses=step_condition_addresses,
            step_predicate_addresses=step_predicate_addresses,
            refresh_dependencies=_dedupe(
                [*objective_addresses, *predicate_dependency_addresses]
            ),
            step_graph=step_graph,
            spec=_dump(workflow),
        )
    return workflows, diagnostics
