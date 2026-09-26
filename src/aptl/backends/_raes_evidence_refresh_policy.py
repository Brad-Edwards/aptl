"""Fail-closed participant policy for evaluator-only evidence refresh."""

from raes_contracts.planning import RuntimeDomain
from raes_contracts.runtime_state import RuntimeSnapshot


class EvidenceRefreshCrossingPolicyResolver:
    """Reject participant crossings while native evidence truth is refreshed."""

    @staticmethod
    def _reject() -> None:
        """Reject all participant policy access in this evaluator phase."""

        raise RuntimeError(
            "participant crossings are unavailable during native-evidence refresh"
        )

    def resolve(self, *_args: object, **_kwargs: object) -> object:
        """Reject an attempted participant crossing."""
        self._reject()

    def validation_context(self, *_args: object, **_kwargs: object) -> object:
        """Reject a request for participant crossing validation context."""
        self._reject()

    def resolve_flow_sink_decision(
        self, *_args: object, **_kwargs: object
    ) -> object:
        """Reject an attempted participant flow-sink decision."""
        self._reject()


def without_evaluation_state(snapshot: RuntimeSnapshot) -> RuntimeSnapshot:
    """Retain realized runtime state while clearing the phase being replayed."""

    entries = {
        address: entry
        for address, entry in snapshot.entries.items()
        if entry.domain != RuntimeDomain.EVALUATION
    }
    return snapshot.with_entries(
        entries,
        evaluation_results={},
        evaluation_history={},
        proposition_truth_results={},
    )
