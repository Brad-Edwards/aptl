"""Backend conformance runner for schema-first runtime contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from textwrap import dedent
from typing import Any

from aptl.core.runtime.capabilities import BackendManifest
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.contracts import (
    BackendManifestModel,
    EvaluationPlanModel,
    EvaluationHistoryEventModel,
    EvaluationResultStateModel,
    OperationReceiptModel,
    OperationStatusModel,
    OrchestrationPlanModel,
    ProvisioningPlanModel,
    RuntimeSnapshotEnvelopeModel,
    WorkflowExecutionStateModel,
    WorkflowHistoryEventModel,
    schema_bundle,
)
from aptl.core.runtime.manager import (
    _evaluation_result_contract_diagnostics,
    _workflow_result_contract_diagnostics,
)
from aptl.core.runtime.models import (
    Diagnostic,
    EvaluationExecutionState,
    RuntimeDomain,
    RuntimeSnapshotEnvelope,
    RuntimeSnapshot,
    Severity,
    SnapshotEntry,
    WorkflowExecutionState,
)
from aptl.core.runtime.planner import plan
from aptl.core.runtime.registry import RuntimeTarget
from aptl.core.sdl import parse_sdl


class BackendCapabilityProfile(str, Enum):
    """Declared runtime surface level for backend conformance."""

    PROVISIONING_ONLY = "provisioning-only"
    ORCHESTRATION_CAPABLE = "orchestration-capable"
    ORCHESTRATION_EVALUATION = "orchestration-evaluation"
    FULL_REMOTE_CONTROL_PLANE = "full-remote-control-plane"


@dataclass(frozen=True)
class ConformanceCaseResult:
    """Result for one fixture or probe case."""

    name: str
    contract_name: str
    valid: bool
    passed: bool
    diagnostics: tuple[Diagnostic, ...] = ()


@dataclass(frozen=True)
class BackendConformanceReport:
    """Machine-friendly conformance result."""

    profile: BackendCapabilityProfile
    passed: bool
    cases: tuple[ConformanceCaseResult, ...] = ()
    contract_versions: dict[str, str] = field(default_factory=dict)
    unsupported_capability_gaps: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


_PROFILE_REQUIREMENTS: dict[BackendCapabilityProfile, frozenset[str]] = {
    BackendCapabilityProfile.PROVISIONING_ONLY: frozenset(
        {
            "backend-manifest-v1",
            "operation-receipt-v1",
            "operation-status-v1",
            "runtime-snapshot-v1",
        }
    ),
    BackendCapabilityProfile.ORCHESTRATION_CAPABLE: frozenset(
        {
            "backend-manifest-v1",
            "operation-receipt-v1",
            "operation-status-v1",
            "runtime-snapshot-v1",
            "workflow-result-envelope-v1",
            "workflow-history-event-stream-v1",
        }
    ),
    BackendCapabilityProfile.ORCHESTRATION_EVALUATION: frozenset(
        {
            "backend-manifest-v1",
            "operation-receipt-v1",
            "operation-status-v1",
            "runtime-snapshot-v1",
            "workflow-result-envelope-v1",
            "workflow-history-event-stream-v1",
            "evaluation-result-envelope-v1",
            "evaluation-history-event-stream-v1",
        }
    ),
    BackendCapabilityProfile.FULL_REMOTE_CONTROL_PLANE: frozenset(
        {
            "backend-manifest-v1",
            "provisioning-plan-v1",
            "orchestration-plan-v1",
            "evaluation-plan-v1",
            "operation-receipt-v1",
            "operation-status-v1",
            "runtime-snapshot-v1",
            "workflow-result-envelope-v1",
            "workflow-history-event-stream-v1",
            "evaluation-result-envelope-v1",
            "evaluation-history-event-stream-v1",
        }
    ),
}


_MODEL_VALIDATORS = {
    "backend-manifest-v1": BackendManifestModel.model_validate,
    "provisioning-plan-v1": ProvisioningPlanModel.model_validate,
    "orchestration-plan-v1": OrchestrationPlanModel.model_validate,
    "evaluation-plan-v1": EvaluationPlanModel.model_validate,
    "operation-receipt-v1": OperationReceiptModel.model_validate,
    "operation-status-v1": OperationStatusModel.model_validate,
    "runtime-snapshot-v1": RuntimeSnapshotEnvelopeModel.model_validate,
    "workflow-result-envelope-v1": WorkflowExecutionStateModel.model_validate,
    "evaluation-result-envelope-v1": EvaluationResultStateModel.model_validate,
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def fixtures_root() -> Path:
    return _repo_root() / "conformance" / "fixtures"


def profiles_root() -> Path:
    return _repo_root() / "conformance" / "profiles"


def required_contracts(
    profile: BackendCapabilityProfile,
) -> frozenset[str]:
    return _PROFILE_REQUIREMENTS[profile]


def _diagnostic(code: str, address: str, message: str) -> Diagnostic:
    return Diagnostic(
        code=code,
        domain="conformance",
        address=address,
        message=message,
        severity=Severity.ERROR,
    )


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_payload(contract_name: str, payload: Any) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    validator = _MODEL_VALIDATORS.get(contract_name)
    if validator is not None:
        try:
            validator(payload)
        except Exception as exc:
            diagnostics.append(
                _diagnostic(
                    "conformance.schema-invalid",
                    contract_name,
                    f"{contract_name} failed contract validation: {exc}",
                )
            )
            return diagnostics
    elif contract_name == "workflow-history-event-stream-v1":
        if not isinstance(payload, list):
            return [
                _diagnostic(
                    "conformance.schema-invalid",
                    contract_name,
                    "workflow history payload must be a list",
                )
            ]
        for index, event in enumerate(payload):
            try:
                WorkflowHistoryEventModel.model_validate(event)
            except Exception as exc:
                diagnostics.append(
                    _diagnostic(
                        "conformance.schema-invalid",
                        f"{contract_name}[{index}]",
                        f"workflow history event is invalid: {exc}",
                    )
                )
    elif contract_name == "evaluation-history-event-stream-v1":
        if not isinstance(payload, list):
            return [
                _diagnostic(
                    "conformance.schema-invalid",
                    contract_name,
                    "evaluation history payload must be a list",
                )
            ]
        for index, event in enumerate(payload):
            try:
                EvaluationHistoryEventModel.model_validate(event)
            except Exception as exc:
                diagnostics.append(
                    _diagnostic(
                        "conformance.schema-invalid",
                        f"{contract_name}[{index}]",
                        f"evaluation history event is invalid: {exc}",
                    )
                )
    else:
        diagnostics.append(
            _diagnostic(
                "conformance.contract-unknown",
                contract_name,
                f"No conformance validator is registered for {contract_name}.",
            )
        )
    return diagnostics


def _snapshot_from_envelope(payload: dict[str, Any]) -> RuntimeSnapshot:
    validated = RuntimeSnapshotEnvelopeModel.model_validate(payload)
    entries = {
        address: SnapshotEntry(
            address=entry.address,
            domain=RuntimeDomain(entry.domain),
            resource_type=entry.resource_type,
            payload=dict(entry.payload),
            ordering_dependencies=tuple(entry.ordering_dependencies),
            refresh_dependencies=tuple(entry.refresh_dependencies),
            status=entry.status,
        )
        for address, entry in validated.entries.items()
    }
    return RuntimeSnapshot(
        entries=entries,
        orchestration_results={
            address: result.model_dump(mode="json")
            for address, result in validated.orchestration_results.items()
        },
        orchestration_history={
            address: [event.model_dump(mode="json") for event in history]
            for address, history in validated.orchestration_history.items()
        },
        evaluation_results={
            address: result.model_dump(mode="json")
            for address, result in validated.evaluation_results.items()
        },
        evaluation_history={
            address: [event.model_dump(mode="json") for event in history]
            for address, history in validated.evaluation_history.items()
        },
        metadata=dict(validated.metadata),
    )


def _semantic_diagnostics(contract_name: str, payload: Any) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if contract_name == "workflow-result-envelope-v1":
        try:
            WorkflowExecutionState.from_payload(payload)
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _diagnostic(
                    "conformance.semantic-invalid",
                    contract_name,
                    f"workflow result semantics are invalid: {exc}",
                )
            )
        return diagnostics
    if contract_name == "evaluation-result-envelope-v1":
        try:
            EvaluationExecutionState.from_payload(payload)
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _diagnostic(
                    "conformance.semantic-invalid",
                    contract_name,
                    f"evaluation result semantics are invalid: {exc}",
                )
            )
        return diagnostics
    if contract_name != "runtime-snapshot-v1":
        return []
    snapshot = _snapshot_from_envelope(payload)
    return [
        *_workflow_result_contract_diagnostics(snapshot),
        *_evaluation_result_contract_diagnostics(snapshot),
    ]


def run_fixture_suite(
    *,
    profile: BackendCapabilityProfile,
    root: Path | None = None,
) -> BackendConformanceReport:
    """Run the checked-in fixture corpus for a backend profile."""

    root = fixtures_root() if root is None else root
    bundle = schema_bundle()
    required = required_contracts(profile)
    cases: list[ConformanceCaseResult] = []
    diagnostics: list[Diagnostic] = []

    for contract_name in sorted(required):
        valid_dir = root / contract_name / "valid"
        invalid_dir = root / contract_name / "invalid"
        if not valid_dir.exists():
            diagnostics.append(
                _diagnostic(
                    "conformance.fixture-missing",
                    contract_name,
                    f"Missing valid fixture directory for {contract_name}.",
                )
            )
            continue

        for path in sorted(valid_dir.glob("*.json")):
            payload = _load_json(path)
            case_diagnostics = [
                *_validate_payload(contract_name, payload),
                *_semantic_diagnostics(contract_name, payload),
            ]
            cases.append(
                ConformanceCaseResult(
                    name=path.stem,
                    contract_name=contract_name,
                    valid=True,
                    passed=not case_diagnostics,
                    diagnostics=tuple(case_diagnostics),
                )
            )

        if invalid_dir.exists():
            for path in sorted(invalid_dir.glob("*.json")):
                payload = _load_json(path)
                case_diagnostics = [
                    *_validate_payload(contract_name, payload),
                    *_semantic_diagnostics(contract_name, payload),
                ]
                cases.append(
                    ConformanceCaseResult(
                        name=path.stem,
                        contract_name=contract_name,
                        valid=False,
                        passed=bool(case_diagnostics),
                        diagnostics=tuple(case_diagnostics),
                    )
                )

    return BackendConformanceReport(
        profile=profile,
        passed=not diagnostics and all(case.passed for case in cases),
        cases=tuple(cases),
        contract_versions={
            name: str(schema.get("title", name))
            for name, schema in bundle.items()
            if name in required
        },
        diagnostics=tuple(diagnostics),
    )


def profile_for_manifest(manifest: BackendManifest) -> BackendCapabilityProfile:
    """Infer the nearest conformance profile for a backend manifest."""

    if manifest.has_orchestrator and manifest.has_evaluator:
        return BackendCapabilityProfile.ORCHESTRATION_EVALUATION
    if manifest.has_orchestrator:
        return BackendCapabilityProfile.ORCHESTRATION_CAPABLE
    return BackendCapabilityProfile.PROVISIONING_ONLY


def _capability_gaps(
    profile: BackendCapabilityProfile,
    target: RuntimeTarget,
) -> tuple[str, ...]:
    gaps: list[str] = []
    if profile in {
        BackendCapabilityProfile.ORCHESTRATION_CAPABLE,
        BackendCapabilityProfile.ORCHESTRATION_EVALUATION,
        BackendCapabilityProfile.FULL_REMOTE_CONTROL_PLANE,
    } and target.orchestrator is None:
        gaps.append("orchestrator")
    if profile in {
        BackendCapabilityProfile.ORCHESTRATION_EVALUATION,
        BackendCapabilityProfile.FULL_REMOTE_CONTROL_PLANE,
    } and target.evaluator is None:
        gaps.append("evaluator")
    return tuple(gaps)


def run_target_conformance(
    target: RuntimeTarget,
    *,
    profile: BackendCapabilityProfile | None = None,
    root: Path | None = None,
) -> BackendConformanceReport:
    """Run fixture conformance for a target's declared runtime surface."""

    effective_profile = profile or profile_for_manifest(target.manifest)
    fixture_report = run_fixture_suite(profile=effective_profile, root=root)
    gaps = _capability_gaps(effective_profile, target)
    passed = fixture_report.passed and not gaps
    diagnostics = list(fixture_report.diagnostics)
    if gaps:
        diagnostics.append(
            _diagnostic(
                "conformance.unsupported-surface",
                target.name,
                "Target is missing required runtime surfaces: " + ", ".join(gaps),
            )
        )
    live_cases = _live_target_cases(target, effective_profile)
    cases = tuple((*fixture_report.cases, *live_cases))
    passed = passed and all(case.passed for case in live_cases)
    return BackendConformanceReport(
        profile=effective_profile,
        passed=passed,
        cases=cases,
        contract_versions=dict(fixture_report.contract_versions),
        unsupported_capability_gaps=gaps,
        diagnostics=tuple(diagnostics),
    )


def _live_target_cases(
    target: RuntimeTarget,
    profile: BackendCapabilityProfile,
) -> tuple[ConformanceCaseResult, ...]:
    cases: list[ConformanceCaseResult] = []
    manifest_payload = BackendManifestModel.model_validate(
        {
            "schema_version": "backend-manifest/v1",
            "name": target.manifest.name,
            "provisioner": {
                "name": target.manifest.provisioner.name,
                "supported_node_types": sorted(target.manifest.provisioner.supported_node_types),
                "supported_os_families": sorted(target.manifest.provisioner.supported_os_families),
                "supported_content_types": sorted(target.manifest.provisioner.supported_content_types),
                "supported_account_features": sorted(target.manifest.provisioner.supported_account_features),
                "max_total_nodes": target.manifest.provisioner.max_total_nodes,
                "supports_acls": target.manifest.provisioner.supports_acls,
                "supports_accounts": target.manifest.provisioner.supports_accounts,
                "constraints": dict(target.manifest.provisioner.constraints),
            },
            "orchestrator": (
                {
                    "name": target.manifest.orchestrator.name,
                    "supported_sections": sorted(target.manifest.orchestrator.supported_sections),
                    "supports_workflows": target.manifest.orchestrator.supports_workflows,
                    "supports_condition_refs": target.manifest.orchestrator.supports_condition_refs,
                    "supports_inject_bindings": target.manifest.orchestrator.supports_inject_bindings,
                    "supported_workflow_features": sorted(
                        feature.value for feature in target.manifest.orchestrator.supported_workflow_features
                    ),
                    "supported_workflow_state_predicates": sorted(
                        feature.value for feature in target.manifest.orchestrator.supported_workflow_state_predicates
                    ),
                    "constraints": dict(target.manifest.orchestrator.constraints),
                }
                if target.manifest.orchestrator is not None
                else None
            ),
            "evaluator": (
                {
                    "name": target.manifest.evaluator.name,
                    "supported_sections": sorted(target.manifest.evaluator.supported_sections),
                    "supports_scoring": target.manifest.evaluator.supports_scoring,
                    "supports_objectives": target.manifest.evaluator.supports_objectives,
                    "constraints": dict(target.manifest.evaluator.constraints),
                }
                if target.manifest.evaluator is not None
                else None
            ),
        }
    ).model_dump(mode="json")
    manifest_diags = _validate_payload("backend-manifest-v1", manifest_payload)
    cases.append(
        ConformanceCaseResult(
            name="live-manifest",
            contract_name="backend-manifest-v1",
            valid=True,
            passed=not manifest_diags,
            diagnostics=tuple(manifest_diags),
        )
    )

    if profile == BackendCapabilityProfile.PROVISIONING_ONLY:
        return tuple(cases)

    scenario = parse_sdl(
        dedent(
            """
            name: conformance
            nodes:
              vm:
                type: vm
                os: linux
                resources: {ram: 1 gib, cpu: 1}
                conditions: {health: ops}
                roles: {ops: operator}
            conditions:
              health: {command: /bin/true, interval: 15}
            entities:
              blue: {role: blue}
            objectives:
              validate:
                entity: blue
                success: {conditions: [health]}
            workflows:
              response:
                start: run
                steps:
                  run:
                    type: objective
                    objective: validate
                    on-success: finish
                  finish: {type: end}
            """
        )
    )
    execution_plan = plan(compile_runtime_model(scenario), target.manifest)
    control_plane = RuntimeControlPlane(target)
    control_plane.submit_provisioning(execution_plan.provisioning)
    if target.orchestrator is not None:
        control_plane.submit_orchestration(execution_plan.orchestration)
    if target.evaluator is not None:
        control_plane.submit_evaluation(execution_plan.evaluation)
    snapshot_payload = {
        "schema_version": RuntimeSnapshotEnvelope().schema_version,
        "entries": {
            address: {
                "address": entry.address,
                "domain": entry.domain.value,
                "resource_type": entry.resource_type,
                "payload": dict(entry.payload),
                "ordering_dependencies": list(entry.ordering_dependencies),
                "refresh_dependencies": list(entry.refresh_dependencies),
                "status": entry.status,
            }
            for address, entry in control_plane.snapshot.entries.items()
        },
        "orchestration_results": dict(control_plane.snapshot.orchestration_results),
        "orchestration_history": dict(control_plane.snapshot.orchestration_history),
        "evaluation_results": dict(control_plane.snapshot.evaluation_results),
        "evaluation_history": dict(control_plane.snapshot.evaluation_history),
        "metadata": dict(control_plane.snapshot.metadata),
    }
    snapshot_diags = [
        *_validate_payload("runtime-snapshot-v1", snapshot_payload),
        *_semantic_diagnostics("runtime-snapshot-v1", snapshot_payload),
    ]
    cases.append(
        ConformanceCaseResult(
            name="live-snapshot",
            contract_name="runtime-snapshot-v1",
            valid=True,
            passed=not snapshot_diags,
            diagnostics=tuple(snapshot_diags),
        )
    )
    return tuple(cases)
