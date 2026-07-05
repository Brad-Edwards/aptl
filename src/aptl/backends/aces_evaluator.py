"""APTL ACES evaluation adapter.

APTL's full remote-control-plane backend includes this evaluation component for
the objective/condition surface introduced by SCN-010 follow-on #312. APTL's
scenario runtime engine (RTE-001) already evaluates conditions and objectives;
this adapter exposes that surface through the *portable* ACES contracts
``evaluation-result-envelope-v1`` and ``evaluation-history-event-stream-v1``
rather than APTL-native scoring shapes.

The adapter is the ACES ``Evaluator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads an ACES ``EvaluationPlan`` into runtime
state: it registers every evaluation resource as an ACES ``SnapshotEntry`` and,
for each observable evaluation resource, records a truthful
``EvaluationExecutionState`` and then advances observable resources from the
runtime snapshot supplied by the ACES control plane. Conditions observe
provisioning entries, conditional metrics score from those condition results,
and aggregate resources report pass/fail from their compiled dependency
addresses. The adapter never invents elapsed-time score curves; result values
are emitted only when the compiled ACES contract allows them. ``stop()`` clears
evaluation state.

This keeps the full remote-control-plane evaluation claim honest: APTL
publishes the evaluation result/history *contract* surface and the
observed run state behind it, not synthetic in-memory progress.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.evaluation import EvaluationResultContract
from aces_contracts.planning import ChangeAction, EvaluationPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.backends._aces_evaluator_engine import (
    EVALUATION_ADDRESS,
    OBSERVABLE_RESOURCE_TYPES,
    drive_evaluations,
    evaluation_diagnostic,
    existing_states,
    register_evaluation,
    utc_now,
)


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

        entries = dict(working_snapshot.entries)
        states = existing_states(working_snapshot)
        history = {
            address: list(events)
            for address, events in working_snapshot.evaluation_history.items()
        }
        contracts: dict[str, EvaluationResultContract] = {}
        operation_payloads: dict[str, dict[str, object]] = {}
        diagnostics: list[Diagnostic] = []
        changed: list[str] = []
        registered_at = utc_now()

        for op in plan.actionable_operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                states.pop(op.address, None)
                history.pop(op.address, None)
                changed.append(op.address)
                continue
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.EVALUATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="ready",
            )
            changed.append(op.address)
            if op.resource_type in OBSERVABLE_RESOURCE_TYPES:
                contract, evaluation_diagnostics = register_evaluation(
                    op.address,
                    op.payload,
                    registered_at,
                    states,
                    history,
                )
                diagnostics.extend(evaluation_diagnostics)
                if contract is not None:
                    contracts[op.address] = contract
                    operation_payloads[op.address] = dict(op.payload)

        if diagnostics:
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        drive_evaluations(
            plan,
            working_snapshot,
            operation_payloads,
            states,
            history,
            contracts,
        )
        results = {address: state.to_payload() for address, state in states.items()}
        self._results = {address: dict(result) for address, result in results.items()}
        self._history = {
            address: [dict(event) for event in events] for address, events in history.items()
        }
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                entries,
                evaluation_results=results,
                evaluation_history=history,
            ),
            changed_addresses=changed,
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
