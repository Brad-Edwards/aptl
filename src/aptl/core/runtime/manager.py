"""Runtime manager for compiled SDL runtime plans."""

from collections.abc import Iterable
from datetime import UTC, datetime

from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.models import (
    ApplyResult,
    ChangeAction,
    Diagnostic,
    EvaluationExecutionContract,
    EvaluationExecutionState,
    EvaluationHistoryEvent,
    EvaluationHistoryEventType,
    EvaluationResultContract,
    EvaluationResultStatus,
    ExecutionPlan,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    SnapshotEntry,
    WorkflowCompensationStatus,
    WorkflowExecutionContract,
    WorkflowExecutionState,
    WorkflowHistoryEvent,
    WorkflowHistoryEventType,
    WorkflowResultContract,
    WorkflowStatus,
    validate_evaluation_result,
)
from aptl.core.sdl import instantiate_scenario
from aptl.core.semantics.planner import reverse_delete_order
from aptl.core.semantics.workflow import validate_workflow_step_result
from aptl.core.runtime.planner import plan
from aptl.core.runtime.registry import RuntimeTarget, _validate_runtime_target_shape
from aptl.core.sdl.scenario import InstantiatedScenario, Scenario


def _delete_order(entries: dict[str, SnapshotEntry]) -> list[str]:
    return reverse_delete_order(
        {
            address: entry.ordering_dependencies
            for address, entry in entries.items()
        }
    )


def _has_error_diagnostic(diagnostics: list[Diagnostic]) -> bool:
    return any(diagnostic.is_error for diagnostic in diagnostics)


def _failure_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    return Diagnostic(
        code=code,
        domain="runtime",
        address=address,
        message=message,
    )


def _parse_timestamp(raw: str) -> datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _call_backend_diagnostics(
    method,
    *args,
    address: str,
) -> list[Diagnostic]:
    try:
        result = method(*args)
    except Exception as exc:
        return [
            _failure_diagnostic(
                "runtime.backend-call-failed",
                address,
                (
                    f"Backend method '{address}' raised "
                    f"{type(exc).__name__}: {exc}."
                ),
            )
        ]

    if not isinstance(result, Iterable) or isinstance(result, (str, bytes)):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                address,
                (
                    f"Backend method '{address}' returned "
                    f"{type(result).__name__}; expected diagnostics iterable."
                ),
            )
        ]

    diagnostics = list(result)
    if any(not isinstance(diagnostic, Diagnostic) for diagnostic in diagnostics):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                address,
                (
                    f"Backend method '{address}' returned a diagnostics iterable "
                    "containing non-Diagnostic values."
                ),
            )
        ]

    return diagnostics


def _call_backend_apply(
    method,
    *args,
    address: str,
    snapshot: RuntimeSnapshot,
) -> ApplyResult:
    try:
        result = method(*args)
    except Exception as exc:
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-call-failed",
                    address,
                    (
                        f"Backend method '{address}' raised "
                        f"{type(exc).__name__}: {exc}."
                    ),
                )
            ],
        )

    if not isinstance(result, ApplyResult):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned "
                        f"{type(result).__name__}; expected ApplyResult."
                    ),
                )
            ],
        )

    if not isinstance(result.snapshot, RuntimeSnapshot):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned ApplyResult.snapshot "
                        f"as {type(result.snapshot).__name__}; expected RuntimeSnapshot."
                    ),
                )
            ],
        )

    if (
        not isinstance(result.diagnostics, Iterable)
        or isinstance(result.diagnostics, (str, bytes))
    ):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned ApplyResult.diagnostics "
                        f"as {type(result.diagnostics).__name__}; expected iterable."
                    ),
                )
            ],
        )

    if any(not isinstance(diagnostic, Diagnostic) for diagnostic in result.diagnostics):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned ApplyResult.diagnostics "
                        "containing non-Diagnostic values."
                    ),
                )
            ],
        )

    if not isinstance(result.changed_addresses, list):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned ApplyResult.changed_addresses "
                        f"as {type(result.changed_addresses).__name__}; expected list."
                    ),
                )
            ],
        )

    if any(not isinstance(changed_address, str) for changed_address in result.changed_addresses):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned ApplyResult.changed_addresses "
                        "containing non-string values."
                    ),
                )
            ],
        )

    if not isinstance(result.details, dict):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned ApplyResult.details "
                        f"as {type(result.details).__name__}; expected dict."
                    ),
                )
            ],
        )

    workflow_result_diagnostics = _workflow_result_contract_diagnostics(result.snapshot)
    if workflow_result_diagnostics:
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=workflow_result_diagnostics,
        )
    evaluation_result_diagnostics = _evaluation_result_contract_diagnostics(
        result.snapshot
    )
    if evaluation_result_diagnostics:
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=evaluation_result_diagnostics,
        )

    return result


def _workflow_result_contract_diagnostics(
    snapshot: RuntimeSnapshot,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if not isinstance(snapshot.orchestration_results, dict):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                "runtime.apply.orchestration-results",
                "RuntimeSnapshot.orchestration_results must be a dict.",
            )
        ]
    if not isinstance(snapshot.orchestration_history, dict):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                "runtime.apply.orchestration-history",
                "RuntimeSnapshot.orchestration_history must be a dict.",
            )
        ]
    workflow_entries = {
        address: entry
        for address, entry in snapshot.entries.items()
        if entry.domain == RuntimeDomain.ORCHESTRATION
        and entry.resource_type == "workflow"
    }

    for workflow_address, workflow_result in snapshot.orchestration_results.items():
        if not isinstance(workflow_address, str):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    "runtime.apply.orchestration-results",
                    "Workflow orchestration result keys must be strings.",
                )
            )
            continue
        if not isinstance(workflow_result, dict):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    (
                        "Workflow orchestration results must use "
                        "plain-data mapping values."
                    ),
                )
            )
            continue

        workflow_entry = workflow_entries.get(workflow_address)
        if workflow_entry is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    (
                        "Workflow orchestration results must correspond to a "
                        "workflow entry in the runtime snapshot."
                    ),
                )
            )
            continue

        payload = workflow_entry.payload
        result_contract_payload = (
            payload.get("result_contract") if isinstance(payload, dict) else None
        )
        execution_contract_payload = (
            payload.get("execution_contract") if isinstance(payload, dict) else None
        )
        if not isinstance(result_contract_payload, dict):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    "Workflow snapshot payload is missing compiled result_contract.",
                )
            )
            continue
        if not isinstance(execution_contract_payload, dict):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    "Workflow snapshot payload is missing compiled execution_contract.",
                )
            )
            continue

        try:
            result_contract = WorkflowResultContract.from_mapping(
                result_contract_payload
            )
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    f"Workflow result_contract is invalid: {exc}",
                )
            )
            continue
        try:
            execution_contract = WorkflowExecutionContract.from_mapping(
                execution_contract_payload
            )
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    f"Workflow execution_contract is invalid: {exc}",
                )
            )
            continue

        try:
            normalized_result = WorkflowExecutionState.from_payload(workflow_result)
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    f"Workflow result payload is invalid: {exc}",
                )
            )
            continue

        history_payload = snapshot.orchestration_history.get(workflow_address, [])
        if not isinstance(history_payload, list):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    "Workflow history payload must be a list of event mappings.",
                )
            )
            continue
        normalized_history: list[WorkflowHistoryEvent] = []
        for event_payload in history_payload:
            try:
                normalized_history.append(WorkflowHistoryEvent.from_payload(event_payload))
            except (TypeError, ValueError) as exc:
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        f"Workflow history payload is invalid: {exc}",
                    )
                )
        if normalized_history:
            previous_timestamp: datetime | None = None
            for event in normalized_history:
                try:
                    current_timestamp = _parse_timestamp(event.timestamp)
                except ValueError as exc:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            workflow_address,
                            f"Workflow history event timestamp is invalid: {exc}",
                        )
                    )
                    continue
                if previous_timestamp is not None and current_timestamp < previous_timestamp:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            workflow_address,
                            "Workflow history timestamps must be monotonic.",
                        )
                    )
                previous_timestamp = current_timestamp

        if normalized_result.state_schema_version != result_contract.state_schema_version:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    (
                        "Workflow result schema version "
                        f"{normalized_result.state_schema_version!r} does not match "
                        f"compiled contract {result_contract.state_schema_version!r}."
                    ),
                )
            )
        if normalized_result.state_schema_version != execution_contract.state_schema_version:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    (
                        "Workflow result schema version "
                        f"{normalized_result.state_schema_version!r} does not match "
                        f"execution contract {execution_contract.state_schema_version!r}."
                    ),
                )
            )

        successful_compensation_steps = {
            step_name
            for step_name, workflow_address_target in execution_contract.compensation_targets.items()
            if workflow_address_target
            and step_name in normalized_result.steps
            and normalized_result.steps[step_name].lifecycle
            == normalized_result.steps[step_name].lifecycle.COMPLETED
            and normalized_result.steps[step_name].outcome is not None
            and normalized_result.steps[step_name].outcome.value == "succeeded"
        }

        if (
            normalized_result.workflow_status
            in {WorkflowStatus.PENDING, WorkflowStatus.RUNNING}
            and normalized_result.compensation_status
            != WorkflowCompensationStatus.NOT_REQUIRED
        ):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    "Non-terminal workflows may not report compensation activity.",
                )
            )

        if (
            execution_contract.compensation_mode == "automatic"
            and normalized_result.workflow_status.value
            in set(execution_contract.compensation_triggers)
            and successful_compensation_steps
            and normalized_result.compensation_status
            == WorkflowCompensationStatus.NOT_REQUIRED
        ):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    "Terminal workflow requires compensation activity for completed compensable steps.",
                )
            )

        unexpected_steps = sorted(
            step_name
            for step_name in normalized_result.steps
            if step_name not in result_contract.observable_steps
        )
        if unexpected_steps:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    (
                        "Workflow results include non-observable or undefined steps: "
                        + ", ".join(unexpected_steps)
                    ),
                )
            )

        missing_steps = sorted(
            step_name
            for step_name in result_contract.observable_steps
            if step_name not in normalized_result.steps
        )
        if missing_steps:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    workflow_address,
                    (
                        "Workflow results must include all observable steps: "
                        + ", ".join(missing_steps)
                    ),
                )
            )

        for step_name, step_state in normalized_result.steps.items():
            contract = result_contract.observable_steps.get(step_name)
            if contract is None:
                continue
            violations = validate_workflow_step_result(
                contract,
                lifecycle=step_state.lifecycle.value,
                outcome=step_state.outcome.value if step_state.outcome else None,
                attempts=step_state.attempts,
            )
            for violation in violations:
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        f"{workflow_address}.{step_name}",
                        violation,
                    )
                )

        for step_name, step_state in normalized_result.steps.items():
            if step_name not in execution_contract.steps:
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        f"Workflow results reference unknown step '{step_name}'.",
                    )
                )
                continue
            if step_state.lifecycle == step_state.lifecycle.COMPLETED:
                step_contract = execution_contract.steps[step_name]
                if (
                    step_state.outcome is not None
                    and step_contract.state_observable
                    and step_state.outcome.value not in step_contract.observable_outcomes
                ):
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            f"{workflow_address}.{step_name}",
                            (
                                f"Completed step reports outcome {step_state.outcome.value!r} "
                                f"outside execution contract domain "
                                f"{step_contract.observable_outcomes!r}."
                            ),
                        )
                    )

        terminal_event_types = {
            WorkflowStatus.SUCCEEDED: WorkflowHistoryEventType.WORKFLOW_COMPLETED,
            WorkflowStatus.FAILED: WorkflowHistoryEventType.WORKFLOW_FAILED,
            WorkflowStatus.CANCELLED: WorkflowHistoryEventType.WORKFLOW_CANCELLED,
            WorkflowStatus.TIMED_OUT: WorkflowHistoryEventType.WORKFLOW_TIMED_OUT,
        }
        if normalized_history:
            compensation_event_types = {
                WorkflowHistoryEventType.COMPENSATION_REGISTERED,
                WorkflowHistoryEventType.COMPENSATION_STARTED,
                WorkflowHistoryEventType.COMPENSATION_WORKFLOW_STARTED,
                WorkflowHistoryEventType.COMPENSATION_WORKFLOW_COMPLETED,
                WorkflowHistoryEventType.COMPENSATION_WORKFLOW_FAILED,
                WorkflowHistoryEventType.COMPENSATION_COMPLETED,
                WorkflowHistoryEventType.COMPENSATION_FAILED,
            }
            if normalized_history[0].event_type != WorkflowHistoryEventType.WORKFLOW_STARTED:
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        "Workflow history must start with workflow_started.",
                    )
                )
            for event in normalized_history:
                if event.step_name and event.step_name not in execution_contract.steps:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            workflow_address,
                            f"Workflow history references unknown step '{event.step_name}'.",
                            )
                        )
                if (
                    event.event_type == WorkflowHistoryEventType.SWITCH_CASE_SELECTED
                    and event.step_name is not None
                    and execution_contract.step_types.get(event.step_name) != "switch"
                ):
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            workflow_address,
                            "switch_case_selected events must reference a switch step.",
                        )
                    )
                if event.event_type in {
                    WorkflowHistoryEventType.CALL_STARTED,
                    WorkflowHistoryEventType.CALL_COMPLETED,
                }:
                    if (
                        event.step_name is None
                        or execution_contract.step_types.get(event.step_name) != "call"
                    ):
                        diagnostics.append(
                            _failure_diagnostic(
                                "runtime.backend-contract-invalid",
                                workflow_address,
                                f"{event.event_type.value} events must reference a call step.",
                            )
                        )
                    elif execution_contract.call_steps.get(event.step_name):
                        expected_workflow = execution_contract.call_steps[event.step_name]
                        actual_workflow = str(
                            event.details.get("workflow_address", "")
                        )
                        if actual_workflow and actual_workflow != expected_workflow:
                            diagnostics.append(
                                _failure_diagnostic(
                                    "runtime.backend-contract-invalid",
                                    workflow_address,
                                    (
                                        f"{event.event_type.value} event workflow "
                                        f"{actual_workflow!r} does not match call target "
                                        f"{expected_workflow!r}."
                                    ),
                                )
                            )
                if event.event_type == WorkflowHistoryEventType.BRANCH_CONVERGED:
                    if event.join_step is None or event.join_step not in execution_contract.join_owners:
                        diagnostics.append(
                            _failure_diagnostic(
                                "runtime.backend-contract-invalid",
                                workflow_address,
                                "branch_converged events must reference a known join_step.",
                            )
                        )
                if event.event_type == WorkflowHistoryEventType.COMPENSATION_REGISTERED:
                    if (
                        event.step_name is None
                        or event.step_name not in execution_contract.compensation_targets
                    ):
                        diagnostics.append(
                            _failure_diagnostic(
                                "runtime.backend-contract-invalid",
                                workflow_address,
                                "compensation_registered events must reference a compensable step.",
                            )
                        )
                if event.event_type in {
                    WorkflowHistoryEventType.COMPENSATION_WORKFLOW_STARTED,
                    WorkflowHistoryEventType.COMPENSATION_WORKFLOW_COMPLETED,
                    WorkflowHistoryEventType.COMPENSATION_WORKFLOW_FAILED,
                }:
                    if (
                        event.step_name is None
                        or event.step_name not in execution_contract.compensation_targets
                    ):
                        diagnostics.append(
                            _failure_diagnostic(
                                "runtime.backend-contract-invalid",
                                workflow_address,
                                f"{event.event_type.value} events must reference a compensable step.",
                            )
                        )
                    else:
                        expected_workflow = execution_contract.compensation_targets[
                            event.step_name
                        ]
                        actual_workflow = str(event.details.get("workflow_address", ""))
                        if actual_workflow and actual_workflow != expected_workflow:
                            diagnostics.append(
                                _failure_diagnostic(
                                    "runtime.backend-contract-invalid",
                                    workflow_address,
                                    (
                                        f"{event.event_type.value} event workflow "
                                        f"{actual_workflow!r} does not match compensation target "
                                        f"{expected_workflow!r}."
                                    ),
                                )
                            )
            expected_terminal = terminal_event_types.get(normalized_result.workflow_status)
            if expected_terminal is not None:
                terminal_indexes = [
                    index
                    for index, event in enumerate(normalized_history)
                    if event.event_type == expected_terminal
                ]
                if not terminal_indexes:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            workflow_address,
                            (
                                "Workflow terminal status "
                                f"{normalized_result.workflow_status.value!r} requires "
                                f"a history event {expected_terminal.value!r}."
                            ),
                        )
                    )
                compensation_indexes = [
                    index
                    for index, event in enumerate(normalized_history)
                    if event.event_type in compensation_event_types
                ]
                if compensation_indexes and terminal_indexes:
                    if terminal_indexes[-1] > compensation_indexes[0]:
                        diagnostics.append(
                            _failure_diagnostic(
                                "runtime.backend-contract-invalid",
                                workflow_address,
                                "Compensation events may only occur after the primary terminal workflow event.",
                            )
                        )
            if normalized_result.workflow_status == WorkflowStatus.RUNNING and normalized_history[-1].event_type in terminal_event_types.values():
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        "Running workflows may not end history with a terminal event.",
                    )
                )
            compensation_events = [
                event for event in normalized_history if event.event_type in compensation_event_types
            ]
            if (
                normalized_result.compensation_status
                == WorkflowCompensationStatus.NOT_REQUIRED
                and compensation_events
            ):
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        "Workflows without compensation activity may not emit compensation events.",
                    )
                )
            if (
                normalized_result.compensation_status
                == WorkflowCompensationStatus.RUNNING
                and not any(
                    event.event_type == WorkflowHistoryEventType.COMPENSATION_STARTED
                    for event in compensation_events
                )
            ):
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        "compensation_status=running requires a compensation_started history event.",
                    )
                )
            if (
                normalized_result.compensation_status
                == WorkflowCompensationStatus.SUCCEEDED
                and compensation_events
                and compensation_events[-1].event_type
                != WorkflowHistoryEventType.COMPENSATION_COMPLETED
            ):
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        "compensation_status=succeeded requires a final compensation_completed history event.",
                    )
                )
            if (
                normalized_result.compensation_status
                == WorkflowCompensationStatus.FAILED
                and compensation_events
                and compensation_events[-1].event_type
                != WorkflowHistoryEventType.COMPENSATION_FAILED
            ):
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        workflow_address,
                        "compensation_status=failed requires a final compensation_failed history event.",
                    )
                )

    return diagnostics


def _evaluation_result_contract_diagnostics(
    snapshot: RuntimeSnapshot,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if not isinstance(snapshot.evaluation_results, dict):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                "runtime.apply.evaluation-results",
                "RuntimeSnapshot.evaluation_results must be a dict.",
            )
        ]
    if not isinstance(snapshot.evaluation_history, dict):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                "runtime.apply.evaluation-history",
                "RuntimeSnapshot.evaluation_history must be a dict.",
            )
        ]

    evaluation_entries = {
        address: entry
        for address, entry in snapshot.entries.items()
        if entry.domain == RuntimeDomain.EVALUATION
    }
    observable_entries = {
        address: entry
        for address, entry in evaluation_entries.items()
        if isinstance(entry.payload, dict)
        and isinstance(entry.payload.get("result_contract"), dict)
        and isinstance(entry.payload.get("execution_contract"), dict)
    }

    missing_results = sorted(
        address for address in observable_entries if address not in snapshot.evaluation_results
    )
    if missing_results:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                "runtime.apply.evaluation-results",
                (
                    "Evaluation results must include all observable evaluation addresses: "
                    + ", ".join(missing_results)
                ),
            )
        )

    for evaluation_address, evaluation_result in snapshot.evaluation_results.items():
        if not isinstance(evaluation_address, str):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    "runtime.apply.evaluation-results",
                    "Evaluation result keys must be strings.",
                )
            )
            continue
        if not isinstance(evaluation_result, dict):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    "Evaluation results must use plain-data mapping values.",
                )
            )
            continue

        evaluation_entry = observable_entries.get(evaluation_address)
        if evaluation_entry is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    (
                        "Evaluation results must correspond to an observable evaluation "
                        "entry in the runtime snapshot."
                    ),
                )
            )
            continue

        payload = evaluation_entry.payload
        result_contract_payload = (
            payload.get("result_contract") if isinstance(payload, dict) else None
        )
        execution_contract_payload = (
            payload.get("execution_contract") if isinstance(payload, dict) else None
        )
        if not isinstance(result_contract_payload, dict):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    "Evaluation snapshot payload is missing compiled result_contract.",
                )
            )
            continue
        if not isinstance(execution_contract_payload, dict):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    "Evaluation snapshot payload is missing compiled execution_contract.",
                )
            )
            continue

        try:
            result_contract = EvaluationResultContract.from_mapping(
                result_contract_payload
            )
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    f"Evaluation result_contract is invalid: {exc}",
                )
            )
            continue

        try:
            execution_contract = EvaluationExecutionContract.from_mapping(
                execution_contract_payload
            )
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    f"Evaluation execution_contract is invalid: {exc}",
                )
            )
            continue

        try:
            normalized_result = EvaluationExecutionState.from_payload(evaluation_result)
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    f"Evaluation result payload is invalid: {exc}",
                )
            )
            continue

        history_payload = snapshot.evaluation_history.get(evaluation_address)
        if history_payload is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    "Evaluation results must include a history stream for each observable address.",
                )
            )
            continue
        if not isinstance(history_payload, list):
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    "Evaluation history payload must be a list of event mappings.",
                )
            )
            continue
        normalized_history: list[EvaluationHistoryEvent] = []
        for event_payload in history_payload:
            try:
                normalized_history.append(EvaluationHistoryEvent.from_payload(event_payload))
            except (TypeError, ValueError) as exc:
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        evaluation_address,
                        f"Evaluation history payload is invalid: {exc}",
                    )
                )
        if normalized_history:
            previous_timestamp = None
            for event in normalized_history:
                try:
                    current_timestamp = _parse_timestamp(event.timestamp)
                except ValueError as exc:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            evaluation_address,
                            f"Evaluation history event timestamp is invalid: {exc}",
                        )
                    )
                    continue
                if previous_timestamp is not None and current_timestamp < previous_timestamp:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            evaluation_address,
                            "Evaluation history timestamps must be monotonic.",
                        )
                    )
                previous_timestamp = current_timestamp

        if normalized_result.state_schema_version != result_contract.state_schema_version:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    (
                        "Evaluation result schema version "
                        f"{normalized_result.state_schema_version!r} does not match "
                        f"compiled contract {result_contract.state_schema_version!r}."
                    ),
                )
            )
        if normalized_result.state_schema_version != execution_contract.state_schema_version:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    (
                        "Evaluation result schema version "
                        f"{normalized_result.state_schema_version!r} does not match "
                        f"execution contract {execution_contract.state_schema_version!r}."
                    ),
                )
            )
        violations = validate_evaluation_result(result_contract, normalized_result)
        for violation in violations:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    violation,
                )
            )

        if normalized_result.status.value not in execution_contract.allowed_statuses:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    evaluation_address,
                    (
                        "Evaluation result status "
                        f"{normalized_result.status.value!r} is outside execution contract "
                        f"{execution_contract.allowed_statuses!r}."
                    ),
                )
            )
        if normalized_history:
            if (
                execution_contract.requires_start_event
                and normalized_history[0].event_type
                != EvaluationHistoryEventType.EVALUATION_STARTED
            ):
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        evaluation_address,
                        "Evaluation history must start with evaluation_started.",
                    )
                )
            for event in normalized_history:
                if event.event_type.value not in execution_contract.history_event_types:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            evaluation_address,
                            (
                                "Evaluation history event type "
                                f"{event.event_type.value!r} is outside execution contract "
                                f"{execution_contract.history_event_types!r}."
                            ),
                        )
                    )
                if event.status.value not in execution_contract.allowed_statuses:
                    diagnostics.append(
                        _failure_diagnostic(
                            "runtime.backend-contract-invalid",
                            evaluation_address,
                            (
                                "Evaluation history status "
                                f"{event.status.value!r} is outside execution contract "
                                f"{execution_contract.allowed_statuses!r}."
                            ),
                        )
                    )
            expected_final_event = {
                EvaluationResultStatus.READY: EvaluationHistoryEventType.EVALUATION_READY,
                EvaluationResultStatus.FAILED: EvaluationHistoryEventType.EVALUATION_FAILED,
            }.get(normalized_result.status)
            if (
                expected_final_event is not None
                and normalized_history[-1].event_type != expected_final_event
            ):
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        evaluation_address,
                        (
                            "Evaluation result status "
                            f"{normalized_result.status.value!r} requires final history event "
                            f"{expected_final_event.value!r}."
                        ),
                    )
                )
            if normalized_result.status == EvaluationResultStatus.RUNNING and normalized_history[-1].event_type in {
                EvaluationHistoryEventType.EVALUATION_READY,
                EvaluationHistoryEventType.EVALUATION_FAILED,
            }:
                diagnostics.append(
                    _failure_diagnostic(
                        "runtime.backend-contract-invalid",
                        evaluation_address,
                        "Running evaluation results may not end history with a terminal event.",
                    )
                )

    return diagnostics


def _provenance_diagnostics(
    execution_plan: ExecutionPlan,
    target: RuntimeTarget,
    snapshot: RuntimeSnapshot,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if execution_plan.target_name is None:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-target-unbound",
                "runtime.apply",
                (
                    "Execution plan is not bound to a runtime target. Use "
                    "RuntimeManager.plan() or pass target_name explicitly."
                ),
            )
        )
    elif execution_plan.target_name != target.name:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-target-mismatch",
                "runtime.apply",
                (
                    f"Execution plan targets '{execution_plan.target_name}', "
                    f"but manager target is '{target.name}'."
                ),
            )
        )
    if execution_plan.manifest != target.manifest:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-manifest-mismatch",
                "runtime.apply",
                "Execution plan manifest does not match the manager target manifest.",
            )
        )
    if execution_plan.base_snapshot != snapshot:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-snapshot-mismatch",
                "runtime.apply",
                "Execution plan base snapshot does not match the manager snapshot.",
            )
        )
    return diagnostics


def _maybe_synthesize_failure(
    diagnostics: list[Diagnostic],
    *,
    result: ApplyResult,
    code: str,
    address: str,
    message: str,
) -> None:
    if not result.success and not _has_error_diagnostic(result.diagnostics):
        diagnostics.append(_failure_diagnostic(code, address, message))


def _rollback_services(
    snapshot: RuntimeSnapshot,
    services: list[tuple[str, object]],
) -> ApplyResult:
    working_snapshot = snapshot
    diagnostics: list[Diagnostic] = []
    changed_addresses: list[str] = []
    success = True

    for address, service in services:
        stop_result = _call_backend_apply(
            service.stop,
            working_snapshot,
            address=address,
            snapshot=working_snapshot,
        )
        diagnostics.extend(stop_result.diagnostics)
        changed_addresses.extend(stop_result.changed_addresses)
        working_snapshot = stop_result.snapshot
        if not stop_result.success:
            success = False
            _maybe_synthesize_failure(
                diagnostics,
                result=stop_result,
                code="runtime.apply-rollback-failed",
                address=address,
                message=f"Rollback failed while stopping '{address}'.",
            )

    return ApplyResult(
        success=success,
        snapshot=working_snapshot,
        diagnostics=diagnostics,
        changed_addresses=changed_addresses,
    )


class RuntimeManager:
    """Plans and executes SDL runtime work against a target."""

    def __init__(
        self,
        target: RuntimeTarget,
        *,
        initial_snapshot: RuntimeSnapshot | None = None,
    ) -> None:
        _validate_runtime_target_shape(
            manifest=target.manifest,
            provisioner=target.provisioner,
            orchestrator=target.orchestrator,
            evaluator=target.evaluator,
        )
        self._target = target
        self._snapshot = initial_snapshot if initial_snapshot is not None else RuntimeSnapshot()

    @property
    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot

    def plan(
        self,
        scenario: Scenario,
        snapshot: RuntimeSnapshot | None = None,
        *,
        parameters: dict[str, object] | None = None,
        profile: str | None = None,
    ) -> ExecutionPlan:
        concrete_scenario = (
            scenario
            if isinstance(scenario, InstantiatedScenario)
            else instantiate_scenario(scenario, parameters=parameters, profile=profile)
        )
        model = compile_runtime_model(concrete_scenario)
        effective_snapshot = snapshot if snapshot is not None else self._snapshot
        return plan(
            model,
            self._target.manifest,
            effective_snapshot,
            target_name=self._target.name,
        )

    def apply(self, execution_plan: ExecutionPlan) -> ApplyResult:
        diagnostics: list[Diagnostic] = list(execution_plan.diagnostics)
        changed_addresses: list[str] = []

        provenance_diagnostics = _provenance_diagnostics(
            execution_plan,
            self._target,
            self._snapshot,
        )
        diagnostics.extend(provenance_diagnostics)
        if provenance_diagnostics:
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        if not execution_plan.is_valid:
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        evaluation_needed = bool(execution_plan.evaluation.actionable_operations)
        if evaluation_needed and self._target.evaluator is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.apply-missing-evaluator",
                    "runtime.apply.evaluator",
                    "Execution plan requires an evaluator, but the target does not provide one.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        orchestration_needed = bool(execution_plan.orchestration.actionable_operations)
        if orchestration_needed and self._target.orchestrator is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.apply-missing-orchestrator",
                    "runtime.apply.orchestrator",
                    "Execution plan requires an orchestrator, but the target does not provide one.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        validation = _call_backend_diagnostics(
            self._target.provisioner.validate,
            execution_plan.provisioning,
            address="runtime.apply.provisioning.validate",
        )
        diagnostics.extend(validation)
        if _has_error_diagnostic(validation):
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        working_snapshot = execution_plan.base_snapshot
        provision_result = _call_backend_apply(
            self._target.provisioner.apply,
            execution_plan.provisioning,
            working_snapshot,
            address="runtime.apply.provisioning",
            snapshot=working_snapshot,
        )
        diagnostics.extend(provision_result.diagnostics)
        changed_addresses.extend(provision_result.changed_addresses)
        working_snapshot = provision_result.snapshot
        if not provision_result.success:
            _maybe_synthesize_failure(
                diagnostics,
                result=provision_result,
                code="runtime.apply-phase-failed",
                address="runtime.apply.provisioning",
                message="Provisioning apply failed.",
            )
            self._snapshot = working_snapshot
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
                changed_addresses=changed_addresses,
            )

        started_evaluator = False
        if evaluation_needed and self._target.evaluator is not None:
            evaluation_result = _call_backend_apply(
                self._target.evaluator.start,
                execution_plan.evaluation,
                working_snapshot,
                address="runtime.apply.evaluator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(evaluation_result.diagnostics)
            changed_addresses.extend(evaluation_result.changed_addresses)
            working_snapshot = evaluation_result.snapshot
            if evaluation_result.success:
                started_evaluator = True
            else:
                _maybe_synthesize_failure(
                    diagnostics,
                    result=evaluation_result,
                    code="runtime.apply-phase-failed",
                    address="runtime.apply.evaluator",
                    message="Evaluator failed to start.",
                )
                rollback_result = _rollback_services(
                    working_snapshot,
                    [("runtime.rollback.evaluator", self._target.evaluator)],
                )
                diagnostics.extend(rollback_result.diagnostics)
                changed_addresses.extend(rollback_result.changed_addresses)
                working_snapshot = rollback_result.snapshot
                self._snapshot = working_snapshot
                return ApplyResult(
                    success=False,
                    snapshot=self._snapshot,
                    diagnostics=diagnostics,
                    changed_addresses=changed_addresses,
                )

        if orchestration_needed and self._target.orchestrator is not None:
            orchestration_result = _call_backend_apply(
                self._target.orchestrator.start,
                execution_plan.orchestration,
                working_snapshot,
                address="runtime.apply.orchestrator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(orchestration_result.diagnostics)
            changed_addresses.extend(orchestration_result.changed_addresses)
            working_snapshot = orchestration_result.snapshot
            if not orchestration_result.success:
                _maybe_synthesize_failure(
                    diagnostics,
                    result=orchestration_result,
                    code="runtime.apply-phase-failed",
                    address="runtime.apply.orchestrator",
                    message="Orchestrator failed to start.",
                )
                rollback_services = [
                    ("runtime.rollback.orchestrator", self._target.orchestrator),
                ]
                if started_evaluator and self._target.evaluator is not None:
                    rollback_services.append(
                        ("runtime.rollback.evaluator", self._target.evaluator)
                    )
                rollback_result = _rollback_services(working_snapshot, rollback_services)
                diagnostics.extend(rollback_result.diagnostics)
                changed_addresses.extend(rollback_result.changed_addresses)
                working_snapshot = rollback_result.snapshot
                self._snapshot = working_snapshot
                return ApplyResult(
                    success=False,
                    snapshot=self._snapshot,
                    diagnostics=diagnostics,
                    changed_addresses=changed_addresses,
                )

        self._snapshot = working_snapshot
        return ApplyResult(
            success=not _has_error_diagnostic(diagnostics),
            snapshot=self._snapshot,
            diagnostics=diagnostics,
            changed_addresses=changed_addresses,
        )

    def status(self) -> dict[str, object]:
        info: dict[str, object] = {
            "backend": self._target.name,
            "resources": len(self._snapshot.entries),
            "domains": {
                RuntimeDomain.PROVISIONING.value: len(
                    self._snapshot.for_domain(RuntimeDomain.PROVISIONING)
                ),
                RuntimeDomain.ORCHESTRATION.value: len(
                    self._snapshot.for_domain(RuntimeDomain.ORCHESTRATION)
                ),
                RuntimeDomain.EVALUATION.value: len(
                    self._snapshot.for_domain(RuntimeDomain.EVALUATION)
                ),
            },
        }
        if self._target.orchestrator is not None:
            info["orchestrator"] = self._target.orchestrator.status()
            info["orchestration_results"] = self._target.orchestrator.results()
            info["orchestration_history"] = self._target.orchestrator.history()
        if self._target.evaluator is not None:
            info["evaluator"] = self._target.evaluator.status()
            info["evaluation_results"] = self._target.evaluator.results()
            info["evaluation_history"] = self._target.evaluator.history()
        return info

    def destroy(self) -> ApplyResult:
        diagnostics: list[Diagnostic] = []
        changed_addresses: list[str] = []
        working_snapshot = self._snapshot
        phases_succeeded = True

        if self._target.orchestrator is not None:
            stop_result = _call_backend_apply(
                self._target.orchestrator.stop,
                working_snapshot,
                address="runtime.destroy.orchestrator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(stop_result.diagnostics)
            changed_addresses.extend(stop_result.changed_addresses)
            working_snapshot = stop_result.snapshot
            if not stop_result.success:
                phases_succeeded = False
                _maybe_synthesize_failure(
                    diagnostics,
                    result=stop_result,
                    code="runtime.destroy-phase-failed",
                    address="runtime.destroy.orchestrator",
                    message="Orchestrator stop failed.",
                )

        if self._target.evaluator is not None:
            stop_result = _call_backend_apply(
                self._target.evaluator.stop,
                working_snapshot,
                address="runtime.destroy.evaluator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(stop_result.diagnostics)
            changed_addresses.extend(stop_result.changed_addresses)
            working_snapshot = stop_result.snapshot
            if not stop_result.success:
                phases_succeeded = False
                _maybe_synthesize_failure(
                    diagnostics,
                    result=stop_result,
                    code="runtime.destroy-phase-failed",
                    address="runtime.destroy.evaluator",
                    message="Evaluator stop failed.",
                )

        provisioning_entries = working_snapshot.for_domain(RuntimeDomain.PROVISIONING)
        delete_plan = ProvisioningPlan(
            resources={},
            operations=[
                ProvisionOp(
                    action=ChangeAction.DELETE,
                    address=address,
                    resource_type=provisioning_entries[address].resource_type,
                    payload=provisioning_entries[address].payload,
                    ordering_dependencies=(
                        provisioning_entries[address].ordering_dependencies
                    ),
                    refresh_dependencies=(
                        provisioning_entries[address].refresh_dependencies
                    ),
                )
                for address in _delete_order(provisioning_entries)
            ],
        )
        provision_result = _call_backend_apply(
            self._target.provisioner.apply,
            delete_plan,
            working_snapshot,
            address="runtime.destroy.provisioning",
            snapshot=working_snapshot,
        )
        diagnostics.extend(provision_result.diagnostics)
        changed_addresses.extend(provision_result.changed_addresses)
        working_snapshot = provision_result.snapshot
        if not provision_result.success:
            phases_succeeded = False
            _maybe_synthesize_failure(
                diagnostics,
                result=provision_result,
                code="runtime.destroy-phase-failed",
                address="runtime.destroy.provisioning",
                message="Provisioning destroy failed.",
            )

        self._snapshot = working_snapshot
        return ApplyResult(
            success=phases_succeeded and not _has_error_diagnostic(diagnostics),
            snapshot=self._snapshot,
            diagnostics=diagnostics,
            changed_addresses=changed_addresses,
        )
