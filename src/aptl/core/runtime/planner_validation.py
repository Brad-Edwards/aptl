"""Backend-manifest validation across all runtime domains."""

from aptl.core.runtime.capabilities import BackendManifest, ProvisionerCapabilities
from aptl.core.runtime.models import Diagnostic, RuntimeModel
from aptl.core.runtime.planner_capabilities import (
    _resource_count_upper_bound,
    _validate_account_features,
    _validate_node_os_family,
)


def _validate_orchestration(
    model: RuntimeModel,
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Validate orchestration usage against the configured orchestrator capabilities."""
    diagnostics: list[Diagnostic] = []
    orchestration_sections = {
        "injects": bool(model.injects or model.inject_bindings),
        "events": bool(model.events),
        "scripts": bool(model.scripts),
        "stories": bool(model.stories),
        "workflows": bool(model.workflows),
    }
    if not any(orchestration_sections.values()):
        return diagnostics
    if manifest.orchestrator is None:
        diagnostics.append(
            Diagnostic(
                code="orchestrator.missing",
                domain="orchestration",
                address="orchestration",
                message=(
                    "Scenario requires orchestration support, but no "
                    "orchestrator is configured."
                ),
            )
        )
        return diagnostics

    diagnostics.extend(
        _orchestration_section_diagnostics(orchestration_sections, manifest)
    )
    diagnostics.extend(_orchestration_feature_diagnostics(model, manifest))
    return diagnostics


def _orchestration_section_diagnostics(
    orchestration_sections: dict[str, bool],
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Report orchestration sections the configured orchestrator cannot support."""
    diagnostics: list[Diagnostic] = []
    orchestrator = manifest.orchestrator
    if orchestrator is None:
        return diagnostics
    for section, used in orchestration_sections.items():
        if used and section not in orchestrator.supported_sections:
            diagnostics.append(
                Diagnostic(
                    code="orchestrator.unsupported-section",
                    domain="orchestration",
                    address=f"orchestration.{section}",
                    message=f"Orchestrator does not support '{section}'.",
                )
            )
    return diagnostics


def _orchestration_uses_condition_refs(model: RuntimeModel) -> bool:
    """Return whether any event or workflow step references a condition predicate."""
    return any(
        event.condition_addresses for event in model.events.values()
    ) or any(
        addresses
        for workflow in model.workflows.values()
        for addresses in workflow.step_condition_addresses.values()
    )


def _orchestration_feature_diagnostics(
    model: RuntimeModel,
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Report orchestrator feature gaps for workflows, condition refs, and injects."""
    diagnostics: list[Diagnostic] = []
    orchestrator = manifest.orchestrator
    if orchestrator is None:
        return diagnostics
    if model.workflows and not orchestrator.supports_workflows:
        diagnostics.append(
            Diagnostic(
                code="orchestrator.workflows-unsupported",
                domain="orchestration",
                address="orchestration.workflows",
                message="Orchestrator does not support workflows.",
            )
        )
    if _orchestration_uses_condition_refs(model) and not (
        orchestrator.supports_condition_refs
    ):
        diagnostics.append(
            Diagnostic(
                code="orchestrator.condition-refs-unsupported",
                domain="orchestration",
                address="orchestration.condition-refs",
                message=(
                    "Orchestrator does not support condition-gated events "
                    "or workflow predicates."
                ),
            )
        )
    if model.inject_bindings and not orchestrator.supports_inject_bindings:
        diagnostics.append(
            Diagnostic(
                code="orchestrator.inject-bindings-unsupported",
                domain="orchestration",
                address="orchestration.injects",
                message="Orchestrator does not support node-bound injects.",
            )
        )
    return diagnostics


def _validate_evaluation(
    model: RuntimeModel,
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Validate evaluation usage against the configured evaluator capabilities."""
    diagnostics: list[Diagnostic] = []
    evaluation_sections = {
        "conditions": bool(model.condition_bindings),
        "metrics": bool(model.metrics),
        "evaluations": bool(model.evaluations),
        "tlos": bool(model.tlos),
        "goals": bool(model.goals),
        "objectives": bool(model.objectives),
    }
    if not any(evaluation_sections.values()):
        return diagnostics
    if not manifest.has_evaluator:
        diagnostics.append(
            Diagnostic(
                code="evaluator.missing",
                domain="evaluation",
                address="evaluation",
                message=(
                    "Scenario requires evaluation support, but no evaluator "
                    "is configured."
                ),
            )
        )
        return diagnostics

    diagnostics.extend(_evaluation_section_diagnostics(evaluation_sections, manifest))
    diagnostics.extend(_evaluation_feature_diagnostics(model, manifest))
    return diagnostics


def _evaluation_section_diagnostics(
    evaluation_sections: dict[str, bool],
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Report evaluation sections the configured evaluator cannot support."""
    diagnostics: list[Diagnostic] = []
    supported_sections = manifest.evaluator_supported_sections
    for section, used in evaluation_sections.items():
        if used and section not in supported_sections:
            diagnostics.append(
                Diagnostic(
                    code="evaluator.unsupported-section",
                    domain="evaluation",
                    address=f"evaluation.{section}",
                    message=f"Evaluator does not support '{section}'.",
                )
            )
    return diagnostics


def _evaluation_feature_diagnostics(
    model: RuntimeModel,
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Report evaluator feature gaps for scoring resources and objectives."""
    diagnostics: list[Diagnostic] = []
    scoring_in_use = bool(
        model.condition_bindings
        or model.metrics
        or model.evaluations
        or model.tlos
        or model.goals
    )
    if scoring_in_use and not manifest.supports_scoring:
        diagnostics.append(
            Diagnostic(
                code="evaluator.scoring-unsupported",
                domain="evaluation",
                address="evaluation.scoring",
                message="Evaluator does not support scoring resources.",
            )
        )
    if model.objectives and not manifest.supports_objectives:
        diagnostics.append(
            Diagnostic(
                code="evaluator.objectives-unsupported",
                domain="evaluation",
                address="evaluation.objectives",
                message="Evaluator does not support objectives.",
            )
        )
    return diagnostics


def _validate_networks(
    model: RuntimeModel,
    provisioner: ProvisionerCapabilities,
) -> list[Diagnostic]:
    """Validate switch/network resources against provisioner node and ACL support."""
    diagnostics: list[Diagnostic] = []
    for network in model.networks.values():
        if "switch" not in provisioner.supported_node_types:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-node-type",
                    domain="provisioning",
                    address=network.address,
                    message="Provisioner does not support switch/network nodes.",
                )
            )
        if network.spec.get("infrastructure", {}).get("acls") and not (
            provisioner.supports_acls
        ):
            diagnostics.append(
                Diagnostic(
                    code="provisioner.acls-unsupported",
                    domain="provisioning",
                    address=network.address,
                    message="Provisioner does not support ACL declarations.",
                )
            )
    return diagnostics


def _validate_nodes(
    model: RuntimeModel,
    provisioner: ProvisionerCapabilities,
) -> list[Diagnostic]:
    """Validate node deployments against provisioner node-type and OS-family support."""
    diagnostics: list[Diagnostic] = []
    for node in model.node_deployments.values():
        if node.node_type and node.node_type not in provisioner.supported_node_types:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-node-type",
                    domain="provisioning",
                    address=node.address,
                    message=(
                        f"Provisioner does not support node type "
                        f"'{node.node_type}'."
                    ),
                )
            )
        diagnostics.extend(
            _validate_node_os_family(
                model,
                node,
                provisioner.supported_os_families,
            )
        )
    return diagnostics


def _validate_total_nodes(
    model: RuntimeModel,
    provisioner: ProvisionerCapabilities,
) -> list[Diagnostic]:
    """Validate the scenario's total deployable nodes against the provisioner cap."""
    diagnostics: list[Diagnostic] = []
    if provisioner.max_total_nodes is None:
        return diagnostics

    total_nodes = 0
    for resource in [*model.networks.values(), *model.node_deployments.values()]:
        count_upper_bound, warning = _resource_count_upper_bound(model, resource)
        if warning is not None:
            diagnostics.append(warning)
        if count_upper_bound is not None:
            total_nodes += count_upper_bound

    if total_nodes > provisioner.max_total_nodes:
        diagnostics.append(
            Diagnostic(
                code="provisioner.max-total-nodes-exceeded",
                domain="provisioning",
                address="provision",
                message=(
                    f"Scenario requires {total_nodes} deployable nodes/networks, "
                    f"but provisioner maximum is {provisioner.max_total_nodes}."
                ),
            )
        )
    return diagnostics


def _validate_content(
    model: RuntimeModel,
    provisioner: ProvisionerCapabilities,
) -> list[Diagnostic]:
    """Validate content placements against provisioner content-type support."""
    diagnostics: list[Diagnostic] = []
    for content in model.content_placements.values():
        content_type = str(content.spec.get("type", ""))
        if content_type and content_type not in provisioner.supported_content_types:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-content-type",
                    domain="provisioning",
                    address=content.address,
                    message=(
                        f"Provisioner does not support content type "
                        f"'{content_type}'."
                    ),
                )
            )
    return diagnostics


def _validate_manifest(
    model: RuntimeModel,
    manifest: BackendManifest,
) -> list[Diagnostic]:
    """Validate the compiled model against the backend manifest's full capabilities."""
    provisioner = manifest.provisioner
    diagnostics: list[Diagnostic] = []
    diagnostics.extend(_validate_networks(model, provisioner))
    diagnostics.extend(_validate_nodes(model, provisioner))
    diagnostics.extend(_validate_total_nodes(model, provisioner))
    diagnostics.extend(_validate_content(model, provisioner))
    diagnostics.extend(_validate_account_features(model, provisioner))
    diagnostics.extend(_validate_orchestration(model, manifest))
    diagnostics.extend(_validate_evaluation(model, manifest))
    return diagnostics
