"""SDL-to-runtime compiler.

The public entry point is :func:`compile_runtime_model`. The compiler's internal
helpers are split across sibling modules by domain
(``compiler_addresses``, ``compiler_resolvers``, ``compiler_provisioning``,
``compiler_orchestration``, ``compiler_evaluation``) and re-exported here so that
``from aptl.core.runtime.compiler import <name>`` keeps working for every helper.
"""

from dataclasses import dataclass

from aptl.core.runtime.compiler_addresses import (
    _account_address,
    _address,
    _condition_binding_address,
    _content_address,
    _dedupe,
    _dump,
    _evaluation_address,
    _event_address,
    _feature_binding_address,
    _goal_address,
    _inject_address,
    _inject_binding_address,
    _metric_address,
    _network_address,
    _node_address,
    _objective_address,
    _resource_address_for_node,
    _script_address,
    _story_address,
    _template_address,
    _tlo_address,
    _workflow_address,
)
from aptl.core.runtime.compiler_evaluation import (
    _build_condition_bindings,
    _build_evaluations,
    _build_goals,
    _build_metrics,
    _build_objectives,
    _build_tlos,
    _resolve_objective_success_refs,
    _resolve_objective_window,
)
from aptl.core.runtime.compiler_orchestration import (
    _build_events,
    _build_inject_bindings,
    _build_scripts,
    _build_stories,
    _build_workflow_step_edges,
    _build_workflows,
    _resolve_workflow_step_predicate,
)
from aptl.core.runtime.compiler_provisioning import (
    _build_account_placements,
    _build_content_placements,
    _build_feature_bindings,
    _build_node_deployments,
)
from aptl.core.runtime.compiler_resolvers import (
    NodeRefContext,
    _resolve_binding_ref,
    _resolve_binding_refs,
    _resolve_named_refs,
    _resolve_node_ref,
    _resolve_resource_refs,
    _resolve_workflow_step_refs,
)
from aptl.core.runtime.models import (
    Diagnostic,
    InjectRuntime,
    RuntimeModel,
    RuntimeTemplate,
)
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.scenario import Scenario

__all__ = [
    "NodeRefContext",
    "_account_address",
    "_address",
    "_build_account_placements",
    "_build_condition_bindings",
    "_build_content_placements",
    "_build_evaluations",
    "_build_events",
    "_build_feature_bindings",
    "_build_goals",
    "_build_inject_bindings",
    "_build_metrics",
    "_build_node_deployments",
    "_build_objectives",
    "_build_scripts",
    "_build_stories",
    "_build_tlos",
    "_build_workflow_step_edges",
    "_build_workflows",
    "_condition_binding_address",
    "_content_address",
    "_dedupe",
    "_dump",
    "_evaluation_address",
    "_event_address",
    "_feature_binding_address",
    "_goal_address",
    "_inject_address",
    "_inject_binding_address",
    "_metric_address",
    "_network_address",
    "_node_address",
    "_objective_address",
    "_resolve_binding_ref",
    "_resolve_binding_refs",
    "_resolve_named_refs",
    "_resolve_node_ref",
    "_resolve_objective_success_refs",
    "_resolve_objective_window",
    "_resolve_resource_refs",
    "_resolve_workflow_step_predicate",
    "_resolve_workflow_step_refs",
    "_resource_address_for_node",
    "_script_address",
    "_story_address",
    "_template_address",
    "_tlo_address",
    "_workflow_address",
    "compile_runtime_model",
]


@dataclass(frozen=True)
class _RuntimeTemplates:
    """Compiled template maps grouped by SDL template kind."""

    feature: dict[str, RuntimeTemplate]
    condition: dict[str, RuntimeTemplate]
    inject: dict[str, RuntimeTemplate]
    vulnerability: dict[str, RuntimeTemplate]


def _build_template_map(
    kind: str,
    specs: dict[str, object],
) -> dict[str, RuntimeTemplate]:
    """Build a name-to-template map for one SDL template kind."""
    return {
        name: RuntimeTemplate(
            address=_template_address(kind, name),
            name=name,
            spec=_dump(template),
        )
        for name, template in specs.items()
    }


def _build_templates(scenario: Scenario) -> _RuntimeTemplates:
    """Build the feature, condition, inject, and vulnerability templates."""
    return _RuntimeTemplates(
        feature=_build_template_map("feature", scenario.features),
        condition=_build_template_map("condition", scenario.conditions),
        inject=_build_template_map("inject", scenario.injects),
        vulnerability=_build_template_map("vulnerability", scenario.vulnerabilities),
    )


@dataclass(frozen=True)
class _StaticSpecs:
    """Serialized specs for scenario entities that compile without binding."""

    entities: dict[str, dict[str, object]]
    agents: dict[str, dict[str, object]]
    relationships: dict[str, dict[str, object]]
    variables: dict[str, dict[str, object]]


def _build_static_specs(scenario: Scenario) -> _StaticSpecs:
    """Serialize entities, agents, relationships, and variables to specs."""
    return _StaticSpecs(
        entities={
            name: _dump(entity)
            for name, entity in flatten_entities(scenario.entities).items()
        },
        agents={name: _dump(agent) for name, agent in scenario.agents.items()},
        relationships={
            name: _dump(relationship)
            for name, relationship in scenario.relationships.items()
        },
        variables={
            name: _dump(variable) for name, variable in scenario.variables.items()
        },
    )


def _build_injects(
    inject_templates: dict[str, RuntimeTemplate],
) -> dict[str, InjectRuntime]:
    """Build inject runtime resources from compiled inject templates."""
    return {
        _inject_address(name): InjectRuntime(
            address=_inject_address(name),
            name=name,
            spec=template.spec,
        )
        for name, template in inject_templates.items()
    }


def compile_runtime_model(scenario: Scenario) -> RuntimeModel:
    """Compile an SDL scenario into bound runtime objects."""

    diagnostics: list[Diagnostic] = []

    templates = _build_templates(scenario)
    static_specs = _build_static_specs(scenario)

    networks, node_deployments, node_diagnostics = _build_node_deployments(scenario)
    diagnostics.extend(node_diagnostics)

    feature_bindings, feature_binding_diagnostics = _build_feature_bindings(
        scenario,
        templates.feature,
    )
    diagnostics.extend(feature_binding_diagnostics)

    condition_bindings, condition_binding_diagnostics = _build_condition_bindings(
        scenario,
        templates.condition,
    )
    diagnostics.extend(condition_binding_diagnostics)

    injects = _build_injects(templates.inject)

    inject_bindings, inject_binding_diagnostics = _build_inject_bindings(
        scenario,
        templates.inject,
    )
    diagnostics.extend(inject_binding_diagnostics)

    content_placements, content_diagnostics = _build_content_placements(scenario)
    diagnostics.extend(content_diagnostics)

    account_placements, account_diagnostics = _build_account_placements(scenario)
    diagnostics.extend(account_diagnostics)

    events, event_diagnostics = _build_events(
        scenario,
        condition_bindings,
        injects,
        inject_bindings,
    )
    diagnostics.extend(event_diagnostics)

    scripts, script_diagnostics = _build_scripts(scenario)
    diagnostics.extend(script_diagnostics)

    stories, story_diagnostics = _build_stories(scenario)
    diagnostics.extend(story_diagnostics)

    metrics, metric_diagnostics = _build_metrics(scenario, condition_bindings)
    diagnostics.extend(metric_diagnostics)

    evaluations, evaluation_diagnostics = _build_evaluations(scenario)
    diagnostics.extend(evaluation_diagnostics)

    tlos, tlo_diagnostics = _build_tlos(scenario)
    diagnostics.extend(tlo_diagnostics)

    goals, goal_diagnostics = _build_goals(scenario)
    diagnostics.extend(goal_diagnostics)

    objectives, objective_diagnostics = _build_objectives(scenario, condition_bindings)
    diagnostics.extend(objective_diagnostics)

    workflows, workflow_diagnostics = _build_workflows(scenario, condition_bindings)
    diagnostics.extend(workflow_diagnostics)

    return RuntimeModel(
        scenario_name=scenario.name,
        feature_templates=templates.feature,
        condition_templates=templates.condition,
        inject_templates=templates.inject,
        vulnerability_templates=templates.vulnerability,
        entity_specs=static_specs.entities,
        agent_specs=static_specs.agents,
        relationship_specs=static_specs.relationships,
        variable_specs=static_specs.variables,
        networks=networks,
        node_deployments=node_deployments,
        feature_bindings=feature_bindings,
        condition_bindings=condition_bindings,
        injects=injects,
        inject_bindings=inject_bindings,
        content_placements=content_placements,
        account_placements=account_placements,
        events=events,
        scripts=scripts,
        stories=stories,
        workflows=workflows,
        metrics=metrics,
        evaluations=evaluations,
        tlos=tlos,
        goals=goals,
        objectives=objectives,
        diagnostics=diagnostics,
    )
