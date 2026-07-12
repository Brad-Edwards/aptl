"""APTL ACES evaluation adapter.

APTL's full remote-control-plane backend includes this evaluation component for
the objective/condition surface introduced by SCN-010 follow-on #312. APTL's
scenario runtime engine (RTE-001) already evaluates conditions and objectives;
this adapter exposes that surface through the *portable* ACES contracts
``evaluation-result-envelope-v1`` and ``evaluation-history-event-stream-v1``
rather than APTL-native scoring shapes or the deprecated SDL scoring chain.

The adapter is the ACES ``Evaluator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads an ACES ``EvaluationPlan`` into runtime
state: it registers every evaluation resource as an ACES ``SnapshotEntry`` and,
for each supported observable evaluation resource, records a truthful
``EvaluationExecutionState`` and then advances conditions and objectives from
the runtime snapshot supplied by the ACES control plane. Conditions observe
provisioning entries, and objectives report pass/fail from their compiled
condition dependencies. SDL ``metrics``/``evaluations``/``tlos``/``goals`` are
outside APTL's declared evaluator surface after ACES ADR-073 and fail closed if
present in an evaluation plan. ``stop()`` clears evaluation state.

This keeps the full remote-control-plane evaluation claim honest: APTL
publishes the evaluation result/history *contract* surface and the
observed run state behind it, not synthetic in-memory progress.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.evaluation import EvaluationExecutionState, EvaluationResultContract
from aces_contracts.planning import ChangeAction, EvaluationPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.backends._aces_evaluator_engine import (
    EVALUATION_ADDRESS,
    OBSERVABLE_RESOURCE_TYPES,
    UNSUPPORTED_SCORING_RESOURCE_TYPES,
    drive_evaluations,
    evaluation_diagnostic,
    existing_states,
    register_evaluation,
    utc_now,
)


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


def _delete_registered_operation(registration: _EvaluationRegistration, op: object) -> None:
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


def _apply_operation(registration: _EvaluationRegistration, op: object) -> None:
    """Apply one evaluation operation to mutable registration state."""
    if op.action == ChangeAction.DELETE:
        _delete_registered_operation(registration, op)
    elif op.resource_type in UNSUPPORTED_SCORING_RESOURCE_TYPES:
        registration.diagnostics.append(_unsupported_scoring_diagnostic(op))
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
    """ACES evaluation adapter for APTL's full remote-control-plane target."""

    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(default_factory=dict, init=False)

    def start(self, plan: object, snapshot: object) -> ApplyResult:
        """Load an ACES evaluation plan and register its observable resources."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        if not isinstance(plan, EvaluationPlan):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=[
                    evaluation_diagnostic(
                        "aptl.evaluator.invalid-plan",
                        EVALUATION_ADDRESS,
                        "APTL evaluator expected an ACES EvaluationPlan.",
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
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                registration.entries,
                evaluation_results=results,
                evaluation_history=registration.history,
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
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        retained_entries = {
            address: entry
            for address, entry in working_snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        changed = sorted(set(working_snapshot.entries) - set(retained_entries))
        self._results = {}
        self._history = {}
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                retained_entries,
                evaluation_results={},
                evaluation_history={},
            ),
            changed_addresses=changed,
        )
