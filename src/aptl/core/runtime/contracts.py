"""Schema-first external contract models for SDL/runtime boundaries."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aptl.core.runtime.models import (
    OPERATION_SCHEMA_VERSION,
    RUNTIME_SNAPSHOT_SCHEMA_VERSION,
    WORKFLOW_STATE_SCHEMA_VERSION,
)
from aptl.core.sdl.scenario import InstantiatedScenario, Scenario


class ContractModel(BaseModel):
    """Base model for closed-world external contracts."""

    model_config = ConfigDict(extra="forbid")


class InstantiationRequestModel(ContractModel):
    schema_version: Literal["scenario-instantiation/v1"] = "scenario-instantiation/v1"
    profile: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class WorkflowStepStateModel(ContractModel):
    lifecycle: str
    outcome: str | None = None
    attempts: int


class WorkflowExecutionStateModel(ContractModel):
    state_schema_version: Literal[WORKFLOW_STATE_SCHEMA_VERSION] = WORKFLOW_STATE_SCHEMA_VERSION
    workflow_status: str
    run_id: str
    started_at: str
    updated_at: str
    terminal_reason: str | None = None
    steps: dict[str, WorkflowStepStateModel] = Field(default_factory=dict)


class WorkflowHistoryEventModel(ContractModel):
    event_type: str
    timestamp: str
    step_name: str | None = None
    branch_name: str | None = None
    join_step: str | None = None
    outcome: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PlanOperationModel(ContractModel):
    action: str
    address: str
    resource_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    ordering_dependencies: list[str] = Field(default_factory=list)
    refresh_dependencies: list[str] = Field(default_factory=list)


class ProvisioningPlanModel(ContractModel):
    operations: list[PlanOperationModel] = Field(default_factory=list)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)


class OrchestrationPlanModel(ContractModel):
    operations: list[PlanOperationModel] = Field(default_factory=list)
    startup_order: list[str] = Field(default_factory=list)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)


class EvaluationPlanModel(ContractModel):
    operations: list[PlanOperationModel] = Field(default_factory=list)
    startup_order: list[str] = Field(default_factory=list)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)


class SnapshotEntryModel(ContractModel):
    address: str
    domain: str
    resource_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    ordering_dependencies: list[str] = Field(default_factory=list)
    refresh_dependencies: list[str] = Field(default_factory=list)
    status: str = "ready"


class RuntimeSnapshotEnvelopeModel(ContractModel):
    schema_version: Literal[RUNTIME_SNAPSHOT_SCHEMA_VERSION] = RUNTIME_SNAPSHOT_SCHEMA_VERSION
    entries: dict[str, SnapshotEntryModel] = Field(default_factory=dict)
    orchestration_results: dict[str, WorkflowExecutionStateModel] = Field(default_factory=dict)
    orchestration_history: dict[str, list[WorkflowHistoryEventModel]] = Field(default_factory=dict)
    evaluation_results: dict[str, dict[str, Any]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OperationReceiptModel(ContractModel):
    schema_version: Literal[OPERATION_SCHEMA_VERSION] = OPERATION_SCHEMA_VERSION
    operation_id: str
    domain: str
    submitted_at: str
    accepted: bool
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)


class OperationStatusModel(ContractModel):
    schema_version: Literal[OPERATION_SCHEMA_VERSION] = OPERATION_SCHEMA_VERSION
    operation_id: str
    domain: str
    state: str
    submitted_at: str
    updated_at: str
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)
    changed_addresses: list[str] = Field(default_factory=list)


class ProvisionerCapabilitiesModel(ContractModel):
    name: str
    supported_node_types: list[str] = Field(default_factory=list)
    supported_os_families: list[str] = Field(default_factory=list)
    supported_content_types: list[str] = Field(default_factory=list)
    supported_account_features: list[str] = Field(default_factory=list)
    max_total_nodes: int | None = None
    supports_acls: bool = False
    supports_accounts: bool = False
    constraints: dict[str, str] = Field(default_factory=dict)


class OrchestratorCapabilitiesModel(ContractModel):
    name: str
    supported_sections: list[str] = Field(default_factory=list)
    supports_workflows: bool = False
    supports_condition_refs: bool = True
    supports_inject_bindings: bool = True
    supported_workflow_features: list[str] = Field(default_factory=list)
    supported_workflow_state_predicates: list[str] = Field(default_factory=list)
    constraints: dict[str, str] = Field(default_factory=dict)


class EvaluatorCapabilitiesModel(ContractModel):
    name: str
    supported_sections: list[str] = Field(default_factory=list)
    supports_scoring: bool = True
    supports_objectives: bool = True
    constraints: dict[str, str] = Field(default_factory=dict)


class BackendManifestModel(ContractModel):
    schema_version: Literal["backend-manifest/v1"] = "backend-manifest/v1"
    name: str
    provisioner: ProvisionerCapabilitiesModel
    orchestrator: OrchestratorCapabilitiesModel | None = None
    evaluator: EvaluatorCapabilitiesModel | None = None


def schema_bundle() -> dict[str, dict[str, Any]]:
    """Return the repo-published JSON Schemas for external contracts."""

    return {
        "sdl-authoring-input-v1": Scenario.model_json_schema(),
        "instantiated-scenario-v1": InstantiatedScenario.model_json_schema(),
        "scenario-instantiation-request-v1": InstantiationRequestModel.model_json_schema(),
        "backend-manifest-v1": BackendManifestModel.model_json_schema(),
        "provisioning-plan-v1": ProvisioningPlanModel.model_json_schema(),
        "orchestration-plan-v1": OrchestrationPlanModel.model_json_schema(),
        "evaluation-plan-v1": EvaluationPlanModel.model_json_schema(),
        "runtime-snapshot-v1": RuntimeSnapshotEnvelopeModel.model_json_schema(),
        "workflow-result-envelope-v1": WorkflowExecutionStateModel.model_json_schema(),
        "workflow-history-event-stream-v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "WorkflowHistoryEventStream",
            "type": "array",
            "items": WorkflowHistoryEventModel.model_json_schema(),
        },
        "operation-receipt-v1": OperationReceiptModel.model_json_schema(),
        "operation-status-v1": OperationStatusModel.model_json_schema(),
    }
