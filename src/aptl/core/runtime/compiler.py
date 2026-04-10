"""SDL-to-runtime compiler."""

from collections.abc import Callable
from typing import Any

from aptl.core.semantics.objectives import analyze_objective_window
from aptl.core.semantics.workflow import (
    WORKFLOW_STATE_SCHEMA_VERSION,
    workflow_step_semantic_contract,
)
from aptl.core.runtime.capabilities import (
    WorkflowFeature,
    WorkflowStatePredicateFeature,
)
from aptl.core.runtime.models import (
    AccountPlacement,
    ConditionBinding,
    ContentPlacement,
    Diagnostic,
    EvaluationExecutionContract,
    EvaluationResultContract,
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
    ObjectiveWindowReferenceRuntime,
    RuntimeModel,
    RuntimeTemplate,
    ScriptRuntime,
    StoryRuntime,
    TLORuntime,
    WorkflowExecutionContract,
    WorkflowPredicateRuntime,
    WorkflowResultContract,
    WorkflowStepOutcome,
    WorkflowStepStatePredicateRuntime,
    WorkflowStepRuntime,
    WorkflowSwitchCaseRuntime,
    WorkflowRuntime,
)
from aptl.core.sdl import instantiate_scenario
from aptl.core.sdl.orchestration import WorkflowStepType
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import InstantiatedScenario, Scenario


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


def _dedupe_by_value(items: list[Any]) -> tuple[Any, ...]:
    ordered: dict[str, Any] = {}
    for item in items:
        key = getattr(item, "value", repr(item))
        ordered.setdefault(key, item)
    return tuple(item for _, item in sorted(ordered.items()))


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


def _evaluation_contracts(
    resource_type: str,
    spec: dict[str, Any] | None = None,
) -> tuple[EvaluationResultContract, EvaluationExecutionContract]:
    payload = spec or {}
    if resource_type == "metric":
        max_score_raw = payload.get("max-score", payload.get("max_score"))
        fixed_max_score = (
            max_score_raw
            if isinstance(max_score_raw, int) and not isinstance(max_score_raw, bool)
            else None
        )
        return (
            EvaluationResultContract(
                resource_type=resource_type,
                supports_score=True,
                fixed_max_score=fixed_max_score,
            ),
            EvaluationExecutionContract(resource_type=resource_type),
        )
    if resource_type in {
        "condition-binding",
        "evaluation",
        "tlo",
        "goal",
        "objective",
    }:
        return (
            EvaluationResultContract(
                resource_type=resource_type,
                supports_passed=True,
            ),
            EvaluationExecutionContract(resource_type=resource_type),
        )
    return (
        EvaluationResultContract(resource_type=resource_type),
        EvaluationExecutionContract(resource_type=resource_type),
    )


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


def compile_runtime_model(scenario: Scenario | InstantiatedScenario) -> RuntimeModel:
    """Compile an SDL scenario into bound runtime objects."""
    if not isinstance(scenario, InstantiatedScenario):
        scenario = instantiate_scenario(scenario, validate_semantics=False)

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
            address = _feature_binding_address(node_name, feature_name)
            dep_addresses = [node_addr]
            for dep_name in feature.dependencies:
                if dep_name in node.features:
                    dep_addresses.append(_feature_binding_address(node_name, dep_name))
                    continue
                diagnostics.append(
                    Diagnostic(
                        code="provisioning.feature-dependency-binding-missing",
                        domain="provisioning",
                        address=address,
                        message=(
                            f"Feature binding '{feature_name}' on node '{node_name}' "
                            f"requires feature dependency '{dep_name}' to also be "
                            "bound on the same node."
                        ),
                    )
                )
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
            result_contract, execution_contract = _evaluation_contracts(
                "condition-binding"
            )
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
                result_contract=result_contract,
                execution_contract=execution_contract,
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
        result_contract, execution_contract = _evaluation_contracts(
            "metric",
            metric_spec,
        )
        metrics[metric_address] = MetricRuntime(
            address=metric_address,
            name=name,
            condition_name=condition_name,
            condition_addresses=condition_addresses,
            ordering_dependencies=condition_addresses,
            refresh_dependencies=condition_addresses,
            spec=metric_spec,
            result_contract=result_contract,
            execution_contract=execution_contract,
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
        result_contract, execution_contract = _evaluation_contracts("evaluation")
        evaluations[evaluation_address] = EvaluationRuntime(
            address=evaluation_address,
            name=name,
            metric_addresses=metric_addresses,
            ordering_dependencies=metric_addresses,
            refresh_dependencies=metric_addresses,
            spec=_dump(evaluation),
            result_contract=result_contract,
            execution_contract=execution_contract,
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
        result_contract, execution_contract = _evaluation_contracts("tlo")
        tlos[tlo_address] = TLORuntime(
            address=tlo_address,
            name=name,
            evaluation_address=evaluation_address,
            ordering_dependencies=evaluation_addresses,
            refresh_dependencies=evaluation_addresses,
            spec=_dump(tlo),
            result_contract=result_contract,
            execution_contract=execution_contract,
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
        result_contract, execution_contract = _evaluation_contracts("goal")
        goals[goal_address] = GoalRuntime(
            address=goal_address,
            name=name,
            tlo_addresses=tlo_addresses,
            ordering_dependencies=tlo_addresses,
            refresh_dependencies=tlo_addresses,
            spec=_dump(goal),
            result_contract=result_contract,
            execution_contract=execution_contract,
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
        window_references: tuple[ObjectiveWindowReferenceRuntime, ...] = ()
        if objective.window is not None:
            window_analysis = analyze_objective_window(
                story_refs=list(objective.window.stories),
                script_refs=list(objective.window.scripts),
                event_refs=list(objective.window.events),
                workflow_refs=list(objective.window.workflows),
                step_refs=list(objective.window.steps),
                stories_by_name=scenario.stories,
                scripts_by_name=scenario.scripts,
                events_by_name=scenario.events,
                workflows_by_name=scenario.workflows,
            )
            window_story_addresses = _dedupe(
                [_story_address(name) for name in window_analysis.story_names]
            )
            window_script_addresses = _dedupe(
                [_script_address(name) for name in window_analysis.script_names]
            )
            window_event_addresses = _dedupe(
                [_event_address(name) for name in window_analysis.event_names]
            )
            window_workflow_addresses = _dedupe(
                [_workflow_address(name) for name in window_analysis.workflow_names]
            )
            window_step_refs = window_analysis.workflow_step_refs
            window_step_workflow_addresses = _dedupe(
                [
                    _workflow_address(workflow_name)
                    for workflow_name in window_analysis.refresh_workflow_names
                ]
            )
            window_references = tuple(
                ObjectiveWindowReferenceRuntime(
                    raw=ref.raw,
                    canonical_name=ref.canonical_name,
                    reference_kind=ref.reference_kind.value,
                    dependency_roles=tuple(role.value for role in ref.dependency_roles),
                    workflow_name=ref.workflow_name or "",
                    step_name=ref.step_name or "",
                    namespace_path=ref.namespace_path,
                )
                for ref in window_analysis.references
            )
            for issue in window_analysis.issues:
                if issue.code == "story-unbound":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.story-ref-unbound",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' does not resolve to a defined story."
                            ),
                        )
                    )
                elif issue.code == "script-unbound":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.script-ref-unbound",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' does not resolve to a defined script."
                            ),
                        )
                    )
                elif issue.code == "script-outside-window-stories":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.script-ref-outside-window-stories",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' is not included by the objective window's referenced stories."
                            ),
                        )
                    )
                elif issue.code == "event-unbound":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.event-ref-unbound",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' does not resolve to a defined event."
                            ),
                        )
                    )
                elif issue.code == "event-outside-window-scripts":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.event-ref-outside-window-scripts",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' is not included by the objective window's referenced scripts."
                            ),
                        )
                    )
                elif issue.code == "workflow-unbound":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.workflow-ref-unbound",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' does not resolve to a defined workflow."
                            ),
                        )
                    )
                elif issue.code == "step-requires-workflow-window":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.workflow-step-ref-window-missing-workflow",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                "Workflow step references require at least one referenced workflow."
                            ),
                        )
                    )
                elif issue.code == "step-invalid-format":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.workflow-step-ref-invalid-format",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' must use '<workflow>.<step>' syntax."
                            ),
                        )
                    )
                elif issue.code == "step-workflow-unbound":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.workflow-step-ref-workflow-unbound",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' does not resolve to a defined workflow."
                            ),
                        )
                    )
                elif issue.code == "step-workflow-outside-window":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.workflow-step-ref-workflow-outside-window",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' is not part of the objective window's referenced workflows."
                            ),
                        )
                    )
                elif issue.code == "step-unbound":
                    diagnostics.append(
                        Diagnostic(
                            code="evaluation.workflow-step-ref-step-unbound",
                            domain="evaluation",
                            address=objective_address,
                            message=(
                                f"Reference '{issue.ref}' does not resolve to a defined workflow step."
                            ),
                        )
                    )

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
        result_contract, execution_contract = _evaluation_contracts("objective")
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
            window_references=window_references,
            ordering_dependencies=ordering_dependencies,
            refresh_dependencies=refresh_dependencies,
            spec=_dump(objective),
            result_contract=result_contract,
            execution_contract=execution_contract,
        )

    workflows = {}
    for name, workflow in scenario.workflows.items():
        workflow_address = _workflow_address(name)
        join_owners = {
            step.join: step_name
            for step_name, step in workflow.steps.items()
            if step.type == WorkflowStepType.PARALLEL and step.join
        }
        control_steps: dict[str, WorkflowStepRuntime] = {}
        control_edges: dict[str, tuple[str, ...]] = {}
        referenced_objectives: list[str] = []
        step_condition_addresses: dict[str, tuple[str, ...]] = {}
        step_predicate_addresses: dict[str, tuple[str, ...]] = {}
        required_features: list[WorkflowFeature] = []
        required_state_predicate_features: list[
            WorkflowStatePredicateFeature
        ] = []
        compensation_targets: dict[str, str] = {}

        def _compile_workflow_predicate(
            predicate_source,
            *,
            predicate_address: str,
        ) -> tuple[
            WorkflowPredicateRuntime,
            tuple[str, ...],
            tuple[str, ...],
            tuple[str, ...],
            tuple[WorkflowStepStatePredicateRuntime, ...],
        ]:
            condition_addresses, workflow_diagnostics = _resolve_binding_refs(
                condition_bindings,
                ref_names=list(predicate_source.conditions),
                owner_address=predicate_address,
                domain="orchestration",
                code_prefix="orchestration.condition-ref",
                binding_attr="condition_name",
                binding_label="condition",
            )
            diagnostics.extend(workflow_diagnostics)

            predicate_addresses = list(condition_addresses)
            metric_addresses, metric_diagnostics = _resolve_named_refs(
                ref_names=list(predicate_source.metrics),
                available_names=set(scenario.metrics),
                address_builder=_metric_address,
                owner_address=predicate_address,
                domain="orchestration",
                code_prefix="orchestration.metric-ref",
                resource_label="metric",
            )
            evaluation_addresses, evaluation_diagnostics = _resolve_named_refs(
                ref_names=list(predicate_source.evaluations),
                available_names=set(scenario.evaluations),
                address_builder=_evaluation_address,
                owner_address=predicate_address,
                domain="orchestration",
                code_prefix="orchestration.evaluation-ref",
                resource_label="evaluation",
            )
            tlo_addresses, tlo_diagnostics = _resolve_named_refs(
                ref_names=list(predicate_source.tlos),
                available_names=set(scenario.tlos),
                address_builder=_tlo_address,
                owner_address=predicate_address,
                domain="orchestration",
                code_prefix="orchestration.tlo-ref",
                resource_label="TLO",
            )
            goal_addresses, goal_diagnostics = _resolve_named_refs(
                ref_names=list(predicate_source.goals),
                available_names=set(scenario.goals),
                address_builder=_goal_address,
                owner_address=predicate_address,
                domain="orchestration",
                code_prefix="orchestration.goal-ref",
                resource_label="goal",
            )
            predicate_objectives, objective_diagnostics = _resolve_named_refs(
                ref_names=list(predicate_source.objectives),
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

            step_state_predicates = tuple(
                WorkflowStepStatePredicateRuntime(
                    step_name=ref.step,
                    outcomes=tuple(
                        WorkflowStepOutcome(outcome.value)
                        for outcome in ref.outcomes
                    ),
                    min_attempts=ref.min_attempts,
                )
                for ref in predicate_source.steps
                if isinstance(ref.step, str) and ref.step
            )
            return (
                WorkflowPredicateRuntime(
                    condition_addresses=condition_addresses,
                    metric_addresses=tuple(metric_addresses),
                    evaluation_addresses=tuple(evaluation_addresses),
                    tlo_addresses=tuple(tlo_addresses),
                    goal_addresses=tuple(goal_addresses),
                    objective_addresses=tuple(predicate_objectives),
                    step_state_predicates=step_state_predicates,
                ),
                condition_addresses,
                _dedupe(predicate_addresses),
                tuple(predicate_objectives),
                step_state_predicates,
            )

        for step_name, step in workflow.steps.items():
            edges: list[str] = []
            objective_address = ""
            predicate: WorkflowPredicateRuntime | None = None
            switch_cases: tuple[WorkflowSwitchCaseRuntime, ...] = ()
            called_workflow_address = ""
            compensation_workflow_address = ""
            if step.type == WorkflowStepType.OBJECTIVE:
                edges.append(step.on_success)
                if step.on_failure:
                    edges.append(step.on_failure)
            elif step.type == WorkflowStepType.DECISION:
                required_features.append(WorkflowFeature.DECISION)
                edges.extend([step.then_step, step.else_step])
            elif step.type == WorkflowStepType.SWITCH:
                required_features.append(WorkflowFeature.SWITCH)
                edges.extend(case.next_step for case in step.cases)
                edges.append(step.default_step)
            elif step.type == WorkflowStepType.PARALLEL:
                required_features.append(WorkflowFeature.PARALLEL_BARRIER)
                edges.extend(step.branches)
                if step.on_failure:
                    edges.append(step.on_failure)
            elif step.type == WorkflowStepType.JOIN:
                edges.append(step.next)
            elif step.type == WorkflowStepType.RETRY:
                required_features.append(WorkflowFeature.RETRY)
                edges.append(step.on_success)
                if step.on_exhausted:
                    edges.append(step.on_exhausted)
            elif step.type == WorkflowStepType.CALL:
                required_features.append(WorkflowFeature.CALL)
                edges.append(step.on_success)
                if step.on_failure:
                    edges.append(step.on_failure)

            control_edges[step_name] = _dedupe([edge for edge in edges if edge])

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
                objective_address = objective_addresses[0] if objective_addresses else ""
            elif step.workflow:
                workflow_addresses, workflow_diagnostics = _resolve_named_refs(
                    ref_names=[step.workflow],
                    available_names=set(scenario.workflows),
                    address_builder=_workflow_address,
                    owner_address=workflow_address,
                    domain="orchestration",
                    code_prefix="orchestration.workflow-ref",
                    resource_label="workflow",
                )
                diagnostics.extend(workflow_diagnostics)
                called_workflow_address = (
                    workflow_addresses[0] if workflow_addresses else ""
                )
            if step.compensate_with:
                workflow_addresses, workflow_diagnostics = _resolve_named_refs(
                    ref_names=[step.compensate_with],
                    available_names=set(scenario.workflows),
                    address_builder=_workflow_address,
                    owner_address=workflow_address,
                    domain="orchestration",
                    code_prefix="orchestration.workflow-ref",
                    resource_label="workflow",
                )
                diagnostics.extend(workflow_diagnostics)
                compensation_workflow_address = (
                    workflow_addresses[0] if workflow_addresses else ""
                )
                if compensation_workflow_address:
                    compensation_targets[step_name] = compensation_workflow_address
                    required_features.append(WorkflowFeature.COMPENSATION)

            if step.when is not None:
                (
                    predicate,
                    condition_addresses,
                    predicate_addresses,
                    predicate_objectives,
                    step_state_predicates,
                ) = _compile_workflow_predicate(
                    step.when,
                    predicate_address=_address(workflow_address, "step", step_name),
                )
                referenced_objectives.extend(predicate_objectives)
                step_condition_addresses[step_name] = condition_addresses
                step_predicate_addresses[step_name] = predicate_addresses
                if step_state_predicates:
                    required_state_predicate_features.append(
                        WorkflowStatePredicateFeature.OUTCOME_MATCHING
                    )
                if any(
                    state_predicate.min_attempts is not None
                    for state_predicate in step_state_predicates
                ):
                    required_state_predicate_features.append(
                        WorkflowStatePredicateFeature.ATTEMPT_COUNTS
                    )
            elif step.type == WorkflowStepType.SWITCH:
                switch_condition_addresses: list[str] = []
                switch_predicate_addresses: list[str] = []
                compiled_cases: list[WorkflowSwitchCaseRuntime] = []
                for case_index, case in enumerate(step.cases):
                    (
                        case_predicate,
                        condition_addresses,
                        predicate_addresses,
                        predicate_objectives,
                        step_state_predicates,
                    ) = _compile_workflow_predicate(
                        case.when,
                        predicate_address=_address(
                            workflow_address, "step", step_name, "case", str(case_index)
                        ),
                    )
                    referenced_objectives.extend(predicate_objectives)
                    switch_condition_addresses.extend(condition_addresses)
                    switch_predicate_addresses.extend(predicate_addresses)
                    if step_state_predicates:
                        required_state_predicate_features.append(
                            WorkflowStatePredicateFeature.OUTCOME_MATCHING
                        )
                    if any(
                        state_predicate.min_attempts is not None
                        for state_predicate in step_state_predicates
                    ):
                        required_state_predicate_features.append(
                            WorkflowStatePredicateFeature.ATTEMPT_COUNTS
                        )
                    compiled_cases.append(
                        WorkflowSwitchCaseRuntime(
                            case_index=case_index,
                            predicate=case_predicate,
                            next_step=case.next_step,
                        )
                    )
                switch_cases = tuple(compiled_cases)
                if switch_condition_addresses:
                    step_condition_addresses[step_name] = _dedupe(
                        switch_condition_addresses
                    )
                if switch_predicate_addresses:
                    step_predicate_addresses[step_name] = _dedupe(
                        switch_predicate_addresses
                    )

            if (
                step.on_failure
                or step.on_exhausted
            ):
                required_features.append(WorkflowFeature.FAILURE_TRANSITIONS)
            if workflow.timeout is not None:
                required_features.append(WorkflowFeature.TIMEOUTS)
            if workflow.compensation is not None and workflow.compensation.mode.value != "disabled":
                required_features.append(WorkflowFeature.COMPENSATION)

            control_steps[step_name] = WorkflowStepRuntime(
                name=step_name,
                step_type=step.type.value,
                objective_address=objective_address,
                predicate=predicate,
                next_step=step.next,
                on_success=step.on_success,
                on_failure=step.on_failure,
                on_exhausted=step.on_exhausted,
                then_step=step.then_step,
                else_step=step.else_step,
                switch_cases=switch_cases,
                default_step=step.default_step,
                branches=tuple(step.branches),
                join_step=step.join,
                owning_parallel_step=join_owners.get(step_name, ""),
                called_workflow_address=called_workflow_address,
                compensation_workflow_address=compensation_workflow_address,
                max_attempts=step.max_attempts,
                state_contract=workflow_step_semantic_contract(step.type.value),
            )

        objective_addresses = _dedupe(referenced_objectives)
        result_contract_steps = {
            step_name: step_runtime.state_contract
            for step_name, step_runtime in control_steps.items()
            if step_runtime.state_contract.state_observable
        }
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
            start_step=workflow.start,
            referenced_objective_addresses=objective_addresses,
            control_steps=control_steps,
            control_edges=control_edges,
            join_owners=join_owners,
            step_condition_addresses=step_condition_addresses,
            step_predicate_addresses=step_predicate_addresses,
            required_features=_dedupe_by_value(required_features),
            required_state_predicate_features=_dedupe_by_value(
                required_state_predicate_features
            ),
            result_contract=WorkflowResultContract(
                state_schema_version=WORKFLOW_STATE_SCHEMA_VERSION,
                observable_steps=result_contract_steps,
            ),
            execution_contract=WorkflowExecutionContract(
                state_schema_version=WORKFLOW_STATE_SCHEMA_VERSION,
                start_step=workflow.start,
                timeout_seconds=(
                    workflow.timeout.seconds
                    if workflow.timeout is not None
                    and isinstance(workflow.timeout.seconds, int)
                    else None
                ),
                steps={
                    step_name: step_runtime.state_contract
                    for step_name, step_runtime in control_steps.items()
                },
                step_types={
                    step_name: step_runtime.step_type
                    for step_name, step_runtime in control_steps.items()
                },
                control_edges=control_edges,
                join_owners=join_owners,
                call_steps={
                    step_name: step_runtime.called_workflow_address
                    for step_name, step_runtime in control_steps.items()
                    if step_runtime.called_workflow_address
                },
                compensation_mode=(
                    workflow.compensation.mode.value
                    if workflow.compensation is not None
                    else "disabled"
                ),
                compensation_triggers=tuple(
                    trigger.value
                    for trigger in (
                        workflow.compensation.on if workflow.compensation is not None else []
                    )
                ),
                compensation_targets=compensation_targets,
                compensation_ordering=(
                    workflow.compensation.order
                    if workflow.compensation is not None
                    else "reverse_completion"
                ),
                compensation_failure_policy=(
                    workflow.compensation.failure_policy.value
                    if workflow.compensation is not None
                    else "fail_workflow"
                ),
                observable_steps=tuple(sorted(result_contract_steps)),
            ),
            refresh_dependencies=_dedupe(
                [*objective_addresses, *predicate_dependency_addresses]
            ),
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
