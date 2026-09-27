"""Governed runtime snapshot handoff after participant delivery."""

from dataclasses import replace
from typing import Protocol

from raes_contracts.runtime_state import RuntimeSnapshot


class _SnapshotOwner(Protocol):
    """Runtime manager surface required for the governed handoff."""

    _snapshot: RuntimeSnapshot

    @property
    def snapshot(self) -> RuntimeSnapshot:
        """Return the manager-owned current snapshot."""

        ...


def adopt_participant_delivery_snapshot(
    manager: _SnapshotOwner,
    snapshot: RuntimeSnapshot,
) -> RuntimeSnapshot:
    """Resume manager-owned time from a governed participant delivery cut."""

    baseline = replace(
        snapshot,
        participant_control_history=manager.snapshot.participant_control_history,
        participant_crossing_history=manager.snapshot.participant_crossing_history,
    )
    if baseline != manager.snapshot:
        raise ValueError(
            "participant delivery snapshot handoff changed state outside governed history"
        )
    manager._snapshot = snapshot
    return manager.snapshot
