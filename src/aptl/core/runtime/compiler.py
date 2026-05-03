"""SDL-to-runtime compiler."""

from collections.abc import Callable
from typing import Any

from aptl.core.runtime.models import (
    AccountPlacement,
    ConditionBinding,
    ContentPlacement,
    Diagnostic,
    EventRuntime,
    EvaluationRuntime,
    FeatureBinding,
    GoalRuntime,
    InjectRuntime,
    InjectBinding,
    MetricRuntime,
    NetworkRuntime,
    NodeRuntime,
    ObjectiveRuntime,
    RuntimeModel,
    RuntimeTemplate,
    ScriptRuntime,
    StoryRuntime,
    TLORuntime,
    WorkflowRuntime,
)
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario


def _dump(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json", by_alias=True)
    if isinstance(model, dict):
        return dict(model)
    return {}


def _address(*parts: str) -> str:
    return ".".join(part for part in parts if part)


def _dedupe(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _template_address(kind: str, name: str) -> str:
    return _address("template", kind, name)


def _network_address(name: str) -> str:
    return _address("provision", "network", name)


def _node_address(name: str) -> str:
    return _address("provision", "node", name)


def _feature_binding_address(node_name: str, feature_name: str) -> str:
    return _address("provision", "feature", node_name, feature_name)


def _content_address(name: str) -> str:
    return _address("provision", "content", name)


def _account_address(name: str) -> str:
    return _address("provision", "account", name)


def _condition_binding_address(node_name: str, condition_name: str) -> str:
    return _address("evaluation", "condition", node_name, condition_name)


def _inject_address(name: str) -> str:
    return _address("orchestration", "inject", name)


def _inject_binding_address(node_name: str, inject_name: str) -> str:
    return _address("orchestration", "inject-binding", node_name, inject_name)


def _event_address(name: str) -> str:
    return _address("orchestration", "event", name)


def _script_address(name: str) -> str:
    return _address("orchestration", "script", name)


def _story_address(name: str) -> str:
    return _address("orchestration", "story", name)


def _workflow_address(name: str) -> str:
    return _address("orchestration", "workflow", name)


def _metric_address(name: str) -> str:
    return _address("evaluation", "metric", name)


def _evaluation_address(name: str) -> str:
    return _address("evaluation", "evaluation", name)


def _tlo_address(name: str) -> str:
    return _address("evaluation", "tlo", name)


def _goal_address(name: str) -> str:
    return _address("evaluation", "goal", name)


def _objective_address(name: str) -> str:
    return _address("evaluation", "objective", name)


def _resource_address_for_node(scenario: Scenario, node_name: str) -> str:
    node = scenario.nodes.get(node_name)
    if node is not None and node.type == NodeType.SWITCH:
        return _network_address(node_name)
    return _node_address(node_name)


def _resolve_binding_ref(
    bindings: dict[str, Any],
    *,
    ref_name: str,
    owner_address: str,
    domain: str,
    code_prefix: str,
    binding_attr: str,
    binding_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    matches = tuple(
        sorted(
            address
            for address, binding in bindings.items()
            if getattr(binding, binding_attr) == ref_name
        )
    )
    if len(matches) == 1:
        return matches, []

    if not matches:
        return (), [
            Diagnostic(
                code=f"{code_prefix}-unbound",
                domain=domain,
                address=owner_address,
                message=(
                    f"Reference '{ref_name}' does not resolve to a bound "
                    f"{binding_label}."
                ),
            )
        ]

    joined = ", ".join(matches)
    return (), [
        Diagnostic(
            code=f"{code_prefix}-ambiguous",
            domain=domain,
            address=owner_address,
            message=(
                f"Reference '{ref_name}' resolves to multiple bound "
                f"{binding_label}s: {joined}."
            ),
        )
    ]


def _resolve_binding_refs(
    bindings: dict[str, Any],
    *,
    ref_names: list[str],
    owner_address: str,
    domain: str,
    code_prefix: str,
    binding_attr: str,
    binding_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    resolved: list[str] = []
    diagnostics: list[Diagnostic] = []
    for ref_name in dict.fromkeys(ref_names):
        addresses, ref_diagnostics = _resolve_binding_ref(
            bindings,
            ref_name=ref_name,
            owner_address=owner_address,
            domain=domain,
            code_prefix=code_prefix,
            binding_attr=binding_attr,
            binding_label=binding_label,
        )
        resolved.extend(addresses)
        diagnostics.extend(ref_diagnostics)
    return _dedupe(resolved), diagnostics


def _resolve_resource_refs(
    resources: dict[str, Any],
    *,
    ref_names: list[str],
    owner_address: str,
    domain: str,
    code_prefix: str,
    resource_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    resolved: list[str] = []
    diagnostics: list[Diagnostic] = []
    for ref_name in dict.fromkeys(ref_names):
        matched_address = next(
            (
                address
                for address, resource in resources.items()
                if resource.name == ref_name
            ),
            None,
        )
        if matched_address is None:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{ref_name}' does not resolve to a defined "
                        f"{resource_label}."
                    ),
                )
            )
            continue
        resolved.append(matched_address)
    return _dedupe(resolved), diagnostics


def _resolve_named_refs(
    *,
    ref_names: list[str],
    available_names: set[str],
    address_builder: Callable[[str], str],
    owner_address: str,
    domain: str,
    code_prefix: str,
    resource_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    resolved: list[str] = []
    diagnostics: list[Diagnostic] = []
    for ref_name in dict.fromkeys(ref_names):
        if ref_name not in available_names:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{ref_name}' does not resolve to a defined "
                        f"{resource_label}."
                    ),
                )
            )
            continue
        resolved.append(address_builder(ref_name))
    return _dedupe(resolved), diagnostics


def _resolve_node_ref(
    scenario: Scenario,
    *,
    ref_name: str,
    owner_address: str,
    domain: str,
    code_prefix: str,
    node_label: str,
    require_vm: bool = False,
    require_switch: bool = False,
) -> tuple[str | None, list[Diagnostic]]:
    node = scenario.nodes.get(ref_name)
    if node is None:
        return None, [
            Diagnostic(
                code=f"{code_prefix}-unbound",
                domain=domain,
                address=owner_address,
                message=(
                    f"Reference '{ref_name}' does not resolve to a defined "
                    f"{node_label}."
                ),
            )
        ]

    if require_vm and node.type != NodeType.VM:
        return None, [
            Diagnostic(
                code=f"{code_prefix}-invalid-type",
                domain=domain,
                address=owner_address,
                message=(
                    f"Reference '{ref_name}' must resolve to a VM node for "
                    f"{node_label}."
                ),
            )
        ]

    if require_switch and node.type != NodeType.SWITCH:
        return None, [
            Diagnostic(
                code=f"{code_prefix}-invalid-type",
                domain=domain,
                address=owner_address,
                message=(
                    f"Reference '{ref_name}' must resolve to a switch/network "
                    f"node for {node_label}."
                ),
            )
        ]

    return _resource_address_for_node(scenario, ref_name), []


def _resolve_workflow_step_refs(
    scenario: Scenario,
    *,
    step_refs: list[str],
    owner_address: str,
    domain: str,
    code_prefix: str,
) -> tuple[tuple[str, ...], tuple[str, ...], list[Diagnostic]]:
    valid_refs: list[str] = []
    workflow_addresses: list[str] = []
    diagnostics: list[Diagnostic] = []

    for step_ref in dict.fromkeys(step_refs):
        if "." not in step_ref:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-invalid-format",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{step_ref}' must use '<workflow>.<step>' syntax."
                    ),
                )
            )
            continue

        workflow_name, step_name = step_ref.split(".", 1)
        workflow = scenario.workflows.get(workflow_name)
        if workflow is None:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-workflow-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{step_ref}' does not resolve to a defined workflow."
                    ),
                )
            )
            continue
        if step_name not in workflow.steps:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-step-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{step_ref}' does not resolve to a defined workflow step."
                    ),
                )
            )
            continue

        valid_refs.append(step_ref)
        workflow_addresses.append(_workflow_address(workflow_name))

    return _dedupe(valid_refs), _dedupe(workflow_addresses), diagnostics


def compile_runtime_model(scenario: Scenario) -> RuntimeModel:
    """Compile an SDL scenario into bound runtime objects."""

    diagnostics: list[Diagnostic] = []

    feature_templates = {
        name: RuntimeTemplate(
            address=_template_address("feature", name),
            name=name,
            spec=_dump(template),
        )
        for name, template in scenario.features.items()
    }
    condition_templates = {
        name: RuntimeTemplate(
            address=_template_address("condition", name),
            name=name,
            spec=_dump(template),
        )
        for name, template in scenario.conditions.items()
    }
    inject_templates = {
        name: RuntimeTemplate(
            address=_template_address("inject", name),
            name=name,
            spec=_dump(template),
        )
        for name, template in scenario.injects.items()
    }
    vulnerability_templates = {
        name: RuntimeTemplate(
            address=_template_address("vulnerability", name),
            name=name,
            spec=_dump(template),
        )
        for name, template in scenario.vulnerabilities.items()
    }
    entity_specs = {
        name: _dump(entity)
        for name, entity in flatten_entities(scenario.entities).items()
    }
    agent_specs = {name: _dump(agent) for name, agent in scenario.agents.items()}
    relationship_specs = {
        name: _dump(relationship)
        for name, relationship in scenario.relationships.items()
    }
    variable_specs = {
        name: _dump(variable)
        for name, variable in scenario.variables.items()
    }

    networks: dict[str, NetworkRuntime] = {}
    node_deployments: dict[str, NodeRuntime] = {}

    for node_name, node in scenario.nodes.items():
        node_spec = _dump(node)
        infra = scenario.infrastructure.get(node_name)
        infra_spec = _dump(infra) if infra is not None else {}
        ordering_deps: list[str] = []
        refresh_deps: list[str] = []
        if infra is not None:
            for dep_name in infra.dependencies:
                dep_address, dep_diagnostics = _resolve_node_ref(
                    scenario,
                    ref_name=dep_name,
                    owner_address=_resource_address_for_node(scenario, node_name),
                    domain="provisioning",
                    code_prefix="provisioning.infrastructure-dependency-ref",
                    node_label="infrastructure dependency",
                )
                diagnostics.extend(dep_diagnostics)
                if dep_address is not None:
                    ordering_deps.append(dep_address)
                    refresh_deps.append(dep_address)
            for link_name in infra.links:
                link_address, link_diagnostics = _resolve_node_ref(
                    scenario,
                    ref_name=link_name,
                    owner_address=_resource_address_for_node(scenario, node_name),
                    domain="provisioning",
                    code_prefix="provisioning.infrastructure-link-ref",
                    node_label="infrastructure link",
                    require_switch=True,
                )
                diagnostics.extend(link_diagnostics)
                if link_address is not None:
                    ordering_deps.append(link_address)
                    refresh_deps.append(link_address)
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

    feature_bindings: dict[str, FeatureBinding] = {}
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
            dep_addresses = [node_addr]
            for dep_name in feature.dependencies:
                if dep_name in node.features:
                    dep_addresses.append(_feature_binding_address(node_name, dep_name))
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

    condition_bindings: dict[str, ConditionBinding] = {}
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

    injects = {
        _inject_address(name): InjectRuntime(
            address=_inject_address(name),
            name=name,
            spec=template.spec,
        )
        for name, template in inject_templates.items()
    }

    inject_bindings: dict[str, InjectBinding] = {}
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

    content_placements: dict[str, ContentPlacement] = {}
    for name, content in scenario.content.items():
        address = _content_address(name)
        target_address, target_diagnostics = _resolve_node_ref(
            scenario,
            ref_name=content.target,
            owner_address=address,
            domain="provisioning",
            code_prefix="provisioning.content-target-ref",
            node_label="content target",
            require_vm=True,
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

    account_placements: dict[str, AccountPlacement] = {}
    for name, account in scenario.accounts.items():
        address = _account_address(name)
        target_address, target_diagnostics = _resolve_node_ref(
            scenario,
            ref_name=account.node,
            owner_address=address,
            domain="provisioning",
            code_prefix="provisioning.account-node-ref",
            node_label="account node",
            require_vm=True,
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

    events = {}
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

    scripts = {}
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

    stories = {}
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

    metrics = {}
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

    evaluations = {}
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

    tlos = {}
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

    goals = {}
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

    objectives = {}
    for name, objective in scenario.objectives.items():
        objective_address = _objective_address(name)
        success_addresses: list[str] = []
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

        window_story_addresses: tuple[str, ...] = ()
        window_script_addresses: tuple[str, ...] = ()
        window_event_addresses: tuple[str, ...] = ()
        window_workflow_addresses: tuple[str, ...] = ()
        window_step_refs: tuple[str, ...] = ()
        window_step_workflow_addresses: tuple[str, ...] = ()
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

    workflows = {}
    for name, workflow in scenario.workflows.items():
        workflow_address = _workflow_address(name)
        step_graph: dict[str, tuple[str, ...]] = {}
        referenced_objectives: list[str] = []
        step_condition_addresses: dict[str, tuple[str, ...]] = {}
        step_predicate_addresses: dict[str, tuple[str, ...]] = {}

        for step_name, step in workflow.steps.items():
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
            step_graph[step_name] = _dedupe(edges)

            if step.objective:
                objective_addresses, objective_diagnostics = _resolve_named_refs(
                    ref_names=[step.objective],
                    available_names=set(scenario.objectives),
                    address_builder=_objective_address,
                    owner_address=workflow_address,
                    domain="orchestration",
                    code_prefix="orchestration.objective-ref",
                    resource_label="objective",
                )
                diagnostics.extend(objective_diagnostics)
                referenced_objectives.extend(objective_addresses)

            if step.when is None:
                continue

            predicate_address = _address(workflow_address, "step", step_name)
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
            referenced_objectives.extend(predicate_objectives)
            predicate_addresses.extend(predicate_objectives)

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

    return RuntimeModel(
        scenario_name=scenario.name,
        feature_templates=feature_templates,
        condition_templates=condition_templates,
        inject_templates=inject_templates,
        vulnerability_templates=vulnerability_templates,
        entity_specs=entity_specs,
        agent_specs=agent_specs,
        relationship_specs=relationship_specs,
        variable_specs=variable_specs,
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
