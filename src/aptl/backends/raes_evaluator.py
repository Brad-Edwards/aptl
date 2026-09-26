"""APTL RAES evaluation adapter.

APTL's full remote-control-plane backend includes this evaluation component for
the objective/condition surface introduced by SCN-010 follow-on #312. APTL's
scenario runtime engine (RTE-001) already evaluates conditions and objectives;
this adapter exposes that surface through the *portable* RAES contracts
``evaluation-result-envelope-v1`` and ``evaluation-history-event-stream-v1``
rather than APTL-native scoring shapes or the deprecated SDL scoring chain.

The adapter is the RAES ``Evaluator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads a RAES ``EvaluationPlan`` into runtime
state: it registers every evaluation resource as a RAES ``SnapshotEntry`` and,
for each supported observable evaluation resource, records a truthful
``EvaluationExecutionState`` and then advances conditions and objectives from
the runtime snapshot supplied by the RAES control plane. Conditions observe
provisioning entries, and objectives report pass/fail from their compiled
condition dependencies.

Propositions and assertions are admitted as snapshot entries, and their portable
truth is projected into ``proposition_truth_results`` — the backend evaluator's
ADR-069 §3 responsibility. APTL's first concrete slice (issue #889) projects the
ADR-088 service-materialization readback: a boolean observed-state postcondition
corroborated by the realized ``service_materialization`` concern in the snapshot.
An assertion APTL cannot observe gets no truth result — never a fabricated one.
SDL ``metrics``/``evaluations``/``tlos``/``goals`` remain outside APTL's declared
evaluator surface after RAES ADR-073 and fail closed if present. ``stop()``
clears evaluation state.

This keeps the full remote-control-plane evaluation claim honest: APTL
publishes the evaluation result/history *contract* surface and the
observed run state behind it, not synthetic in-memory progress.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from raes_contracts.contracts import ExperimentEvidenceRecordModel
from raes_contracts.diagnostics import Diagnostic
from raes_contracts.evaluation import EvaluationExecutionState, EvaluationResultContract
from raes_contracts.planning import ChangeAction, EvaluationPlan, RuntimeDomain
from raes_contracts.runtime_state import (
    ApplyResult,
    OperationState,
    RuntimeSnapshot,
    SnapshotEntry,
)
from raes_runtime.control_plane import RuntimeControlPlane

from aptl.backends._raes_evidence_refresh_policy import (
    EvidenceRefreshCrossingPolicyResolver,
    without_evaluation_state,
)
from aptl.backends._raes_evaluator_engine import (
    EVALUATION_ADDRESS,
    OBSERVABLE_RESOURCE_TYPES,
    UNSUPPORTED_SCORING_RESOURCE_TYPES,
    drive_evaluations,
    evaluation_diagnostic,
    existing_states,
    register_evaluation,
    utc_now,
)
from aptl.backends._raes_proposition_truth import (
    native_evidence_truth_is_complete,
    project_proposition_truth_results,
)

# Proposition and assertion truth is carried in ``proposition_truth_results``,
# not the condition/objective ``EvaluationResultContract`` path (ADR-069 §3).
# These ops are admitted as snapshot entries and their truth is projected
# separately for the observed-state assertions APTL can corroborate (issue #889).
_PROPOSITION_RESOURCE_TYPES = frozenset({"proposition", "assertion"})

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan
    from raes_runtime.registry import RuntimeTarget


@dataclass
class _EvaluationRegistration(object):
    """Mutable registration state for one evaluator start call."""

    entries: dict[str, SnapshotEntry]
    states: dict[str, EvaluationExecutionState]
    history: dict[str, list[dict[str, object]]]
    contracts: dict[str, EvaluationResultContract] = field(default_factory=dict)
    operation_payloads: dict[str, dict[str, object]] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    registered_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class EvidenceTruthRefresh(object):
    """Terminal result of a post-capture evaluator reconciliation."""

    status: OperationState
    snapshot: RuntimeSnapshot
    diagnostics: tuple[Diagnostic, ...] = ()


def _registration_for_snapshot(snapshot: RuntimeSnapshot) -> _EvaluationRegistration:
    """Build mutable evaluator registration state from the current snapshot."""
    return _EvaluationRegistration(
        entries=dict(snapshot.entries),
        states=existing_states(snapshot),
        history={
            address: list(events)
            for address, events in snapshot.evaluation_history.items()
        },
    )


def _operation_entry(op: object) -> SnapshotEntry:
    """Render an evaluation operation as a runtime snapshot entry."""
    return SnapshotEntry(
        address=op.address,
        domain=RuntimeDomain.EVALUATION,
        resource_type=op.resource_type,
        payload=op.payload,
        ordering_dependencies=op.ordering_dependencies,
        refresh_dependencies=op.refresh_dependencies,
        status="ready",
    )


def _unsupported_scoring_diagnostic(op: object) -> Diagnostic:
    """Return the diagnostic for deprecated SDL scoring-chain resources."""
    return evaluation_diagnostic(
        "aptl.evaluator.unsupported-scoring-section",
        op.address,
        (
            "APTL evaluator supports conditions and objectives; "
            f"SDL scoring resource type {op.resource_type!r} is "
            "outside the declared evaluator surface."
        ),
    )


def _unsupported_score_contract_diagnostic(address: str) -> Diagnostic:
    """Return the diagnostic for score-bearing supported-resource contracts."""
    return evaluation_diagnostic(
        "aptl.evaluator.unsupported-score-contract",
        address,
        (
            "APTL evaluator does not declare scoring support; "
            "condition/objective result contracts must not request score fields."
        ),
    )


def _delete_registered_operation(
    registration: _EvaluationRegistration, op: object
) -> None:
    """Delete an evaluation operation from mutable registration state."""
    registration.entries.pop(op.address, None)
    registration.states.pop(op.address, None)
    registration.history.pop(op.address, None)
    registration.changed.append(op.address)


def _register_observable_operation(
    registration: _EvaluationRegistration,
    op: object,
) -> None:
    """Register the result/history contract for a supported observable operation."""
    contract, diagnostics = register_evaluation(
        op.address,
        op.payload,
        registration.registered_at,
        registration.states,
        registration.history,
    )
    registration.diagnostics.extend(diagnostics)
    if contract is None:
        return
    if contract.supports_score:
        registration.diagnostics.append(
            _unsupported_score_contract_diagnostic(op.address)
        )
        return
    registration.contracts[op.address] = contract
    registration.operation_payloads[op.address] = dict(op.payload)


def _register_supported_operation(
    registration: _EvaluationRegistration,
    op: object,
) -> None:
    """Register a non-scoring evaluation operation."""
    registration.entries[op.address] = _operation_entry(op)
    registration.changed.append(op.address)
    if op.resource_type in OBSERVABLE_RESOURCE_TYPES:
        _register_observable_operation(registration, op)


def _register_admitted_operation(
    registration: _EvaluationRegistration, op: object
) -> None:
    """Admit a proposition/assertion op as a snapshot entry (no result contract).

    Truth for these is projected into ``proposition_truth_results`` after the
    condition/objective outcomes are driven, not through the result-contract
    path, so they are recorded here as admitted entries only.
    """
    registration.entries[op.address] = SnapshotEntry(
        address=op.address,
        domain=RuntimeDomain.EVALUATION,
        resource_type=op.resource_type,
        payload=op.payload,
        ordering_dependencies=op.ordering_dependencies,
        refresh_dependencies=op.refresh_dependencies,
        status="admitted",
    )
    registration.changed.append(op.address)


def _apply_operation(registration: _EvaluationRegistration, op: object) -> None:
    """Apply one evaluation operation to mutable registration state."""
    if op.action == ChangeAction.DELETE:
        _delete_registered_operation(registration, op)
    elif op.resource_type in UNSUPPORTED_SCORING_RESOURCE_TYPES:
        registration.diagnostics.append(_unsupported_scoring_diagnostic(op))
    elif op.resource_type in _PROPOSITION_RESOURCE_TYPES:
        _register_admitted_operation(registration, op)
    else:
        _register_supported_operation(registration, op)


def _apply_plan_operations(
    plan: EvaluationPlan,
    snapshot: RuntimeSnapshot,
) -> _EvaluationRegistration:
    """Apply the evaluation plan operations without driving outcomes."""
    registration = _registration_for_snapshot(snapshot)
    for op in plan.actionable_operations:
        _apply_operation(registration, op)
    return registration


@dataclass
class AptlEvaluator(object):
    """Evaluation component of APTL's ``full-remote-control-plane`` target."""

    proposition_interpreter: Callable[..., object] | None = field(
        default=None, repr=False
    )
    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(
        default_factory=dict, init=False
    )
    _evidence_records: tuple[ExperimentEvidenceRecordModel, ...] = field(
        default=(),
        init=False,
    )

    def bind_evidence_records(
        self,
        records: tuple[ExperimentEvidenceRecordModel, ...],
    ) -> None:
        """Replace the native evidence cut available to proposition evaluation."""

        if any(
            not isinstance(record, ExperimentEvidenceRecordModel) for record in records
        ):
            raise TypeError("APTL evaluator evidence must use RAES evidence records")
        self._evidence_records = records

    def start(self, plan: object, snapshot: object) -> ApplyResult:
        """Load a RAES evaluation plan and register its observable resources."""
        working_snapshot = (
            snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        )
        if not isinstance(plan, EvaluationPlan):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=[
                    evaluation_diagnostic(
                        "aptl.evaluator.invalid-plan",
                        EVALUATION_ADDRESS,
                        "APTL evaluator expected a RAES EvaluationPlan.",
                    )
                ],
            )

        registration = _apply_plan_operations(plan, working_snapshot)

        if registration.diagnostics:
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=registration.diagnostics,
            )

        drive_evaluations(
            plan,
            working_snapshot,
            registration.operation_payloads,
            registration.states,
            registration.history,
            registration.contracts,
        )
        results = {
            address: state.to_payload()
            for address, state in registration.states.items()
        }
        self._results = {address: dict(result) for address, result in results.items()}
        self._history = {
            address: [dict(event) for event in events]
            for address, events in registration.history.items()
        }
        # ADR-069 §3 / issue #889: project truth for the observed-state assertions
        # APTL can corroborate (the service-materialization readback), reading the
        # realized service_materialization concern from the provisioning snapshot.
        truth_results = project_proposition_truth_results(
            plan,
            working_snapshot,
            evidence_records=self._evidence_records,
            proposition_interpreter=self.proposition_interpreter,
        )
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                registration.entries,
                evaluation_results=results,
                evaluation_history=registration.history,
                proposition_truth_results=truth_results,
            ),
            changed_addresses=registration.changed,
        )

    def status(self) -> dict[str, object]:
        """Return current evaluation status."""
        return {
            "backend": "aptl",
            "registered_evaluations": sorted(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        """Return the most recent evaluation result envelopes."""
        return {address: dict(result) for address, result in self._results.items()}

    def history(self) -> dict[str, list[dict[str, object]]]:
        """Return the evaluation history event streams."""
        return {
            address: [dict(event) for event in events]
            for address, events in self._history.items()
        }

    def stop(self, snapshot: object) -> ApplyResult:
        """Stop evaluation and clear evaluation state."""
        working_snapshot = (
            snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        )
        retained_entries = {
            address: entry
            for address, entry in working_snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        changed = sorted(set(working_snapshot.entries) - set(retained_entries))
        self._results = {}
        self._history = {}
        self._evidence_records = ()
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                retained_entries,
                evaluation_results={},
                evaluation_history={},
            ),
            changed_addresses=changed,
        )


def refresh_evidence_truth(
    *,
    target: RuntimeTarget,
    execution_plan: ExecutionPlan,
    snapshot: RuntimeSnapshot,
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
) -> EvidenceTruthRefresh:
    """Reconcile acquired evidence through RAES's runtime control plane.

    The exact planner-produced evaluation phase is resubmitted against the
    post-provisioning snapshot after the evaluator receives the sealed native
    record cut. The control plane remains the sole writer of runtime truth.
    """

    evaluator = target.evaluator
    if not isinstance(evaluator, AptlEvaluator):
        return EvidenceTruthRefresh(
            status=OperationState.FAILED,
            snapshot=snapshot,
            diagnostics=(
                evaluation_diagnostic(
                    "aptl.evaluator.native-evidence-refresh-unavailable",
                    EVALUATION_ADDRESS,
                    "APTL native evidence requires the APTL evaluator.",
                ),
            ),
        )
    evaluator.bind_evidence_records(evidence_records)
    # The planner-produced evaluation operations are immutable CREATEs. The
    # provisioning run already applied them once before native evidence was
    # available, so replaying them against that registered evaluation state is
    # an invalid create-over-existing transition in RAES 5. Rebuild only the
    # evaluation domain from the same observed provisioning snapshot; the new
    # control plane then remains the sole writer of the refreshed truth.
    refresh_snapshot = without_evaluation_state(snapshot)
    control_plane = RuntimeControlPlane(
        target,
        initial_snapshot=refresh_snapshot,
        crossing_policy_resolver=EvidenceRefreshCrossingPolicyResolver(),
    )
    try:
        return _run_evidence_refresh(
            control_plane,
            execution_plan,
            evidence_records,
            evaluator.proposition_interpreter,
        )
    finally:
        control_plane.close()


def _run_evidence_refresh(
    control_plane: RuntimeControlPlane,
    execution_plan: ExecutionPlan,
    evidence_records: tuple[ExperimentEvidenceRecordModel, ...],
    proposition_interpreter: object | None,
) -> EvidenceTruthRefresh:
    """Run one registered evaluation and return its exact terminal disposition."""

    control_plane.register_planner_produced_plan(execution_plan)
    receipt = control_plane.submit_evaluation(execution_plan.evaluation)
    operation = (
        control_plane.get_operation(receipt.operation_id) if receipt.accepted else None
    )
    snapshot = control_plane.snapshot
    if not receipt.accepted:
        result = EvidenceTruthRefresh(
            status=OperationState.FAILED,
            snapshot=snapshot,
            diagnostics=tuple(receipt.diagnostics),
        )
    elif operation is None:
        result = EvidenceTruthRefresh(
            status=OperationState.FAILED,
            snapshot=snapshot,
            diagnostics=(
                evaluation_diagnostic(
                    "aptl.evaluator.native-evidence-refresh-incomplete",
                    EVALUATION_ADDRESS,
                    "RAES did not return a terminal evidence evaluation operation.",
                ),
            ),
        )
    elif (
        operation.state is OperationState.SUCCEEDED
        and not native_evidence_truth_is_complete(
            execution_plan.evaluation,
            snapshot,
            evidence_records,
            proposition_interpreter,
        )
    ):
        result = EvidenceTruthRefresh(
            status=OperationState.FAILED,
            snapshot=snapshot,
            diagnostics=(
                evaluation_diagnostic(
                    "aptl.evaluator.native-evidence-truth-incomplete",
                    EVALUATION_ADDRESS,
                    "Not every required native evidence record decided its exact authored proposition.",
                ),
            ),
        )
    else:
        result = EvidenceTruthRefresh(
            status=operation.state,
            snapshot=snapshot,
            diagnostics=tuple(operation.diagnostics),
        )
    return result
