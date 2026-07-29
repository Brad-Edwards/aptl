"""Terminal-state fixture coverage (EXP-009 acceptance criterion B / ADR-050).

Every terminal cause the execution controller can hand off — success, scenario
failure, infrastructure interruption, capture loss, policy stop, cancellation,
and retry lineage — must seal into a conformant, discoverable ``experiment-run/v1``
record whose marker records the real terminal ``run_status``.
"""

from __future__ import annotations

import json

import pytest
from raes_contracts.contracts import ExperimentReferenceModel, ExperimentRunModel

from tests.archival_fixtures import completed_context
from aptl.core.archival.coordinator import finalize_terminal_attempt
from aptl.core.archival.discovery_index import DiscoveryIndex
from aptl.core.archival.layout import RUN_MANIFEST_RELPATH
from aptl.core.archival.status import TerminalCause
from aptl.core.runstore import LocalRunStore


def _store(tmp_path) -> LocalRunStore:
    return LocalRunStore(tmp_path / "runs")


# (label, terminal_cause, evaluator_outcome, invalidation_reason, expected_run_status)
_TERMINAL_CASES = [
    ("success", TerminalCause.COMPLETED, "succeeded", None, "completed"),
    ("scenario-failure", TerminalCause.SCENARIO_FAILURE, None, None, "failed"),
    (
        "infrastructure-interruption",
        TerminalCause.INFRASTRUCTURE_INTERRUPTION,
        None,
        None,
        "aborted",
    ),
    (
        "capture-loss",
        TerminalCause.CAPTURE_LOSS,
        None,
        "required mid-run capture loss",
        "invalidated",
    ),
    ("policy-stop", TerminalCause.POLICY_STOP, None, None, "aborted"),
    ("cancellation", TerminalCause.CANCELLATION, None, None, "aborted"),
]


@pytest.mark.parametrize(
    ("label", "cause", "outcome", "reason", "expected_status"),
    _TERMINAL_CASES,
    ids=[case[0] for case in _TERMINAL_CASES],
)
def test_every_terminal_state_seals_a_conformant_record(
    tmp_path, label, cause, outcome, reason, expected_status
):
    store = _store(tmp_path)
    context = completed_context(
        terminal_cause=cause, evaluator_outcome=outcome, invalidation_reason=reason
    )
    result = finalize_terminal_attempt(context, store=store)

    assert result.run.run_status == expected_status
    # The sealed manifest is a valid public RAES run record.
    manifest = json.loads(
        (store.get_run_path(context.attempt_id) / RUN_MANIFEST_RELPATH).read_text()
    )
    ExperimentRunModel.model_validate(manifest)
    # The marker records the real terminal status, and the run is discoverable.
    marker = store.read_seal_marker(context.attempt_id)
    assert marker["run_status"] == expected_status
    assert marker["seal_state"] == "sealed"
    assert [e.run_id for e in DiscoveryIndex(store.base_dir).discover()] == [
        context.attempt_id
    ]


def test_retry_lineage_seals_with_predecessor_reference(tmp_path):
    """A retry is a distinct attempt that records its predecessor via RAES refs."""
    store = _store(tmp_path)
    predecessor = ExperimentReferenceModel(
        ref_kind="run", ref_id="run-techvault-000", ref_version="1.0.0"
    )
    context = completed_context(predecessor_run_ref=predecessor)
    result = finalize_terminal_attempt(context, store=store)

    assert predecessor in result.run.derived_from_refs
    manifest = json.loads(
        (store.get_run_path(context.attempt_id) / RUN_MANIFEST_RELPATH).read_text()
    )
    reconstructed = ExperimentRunModel.model_validate(manifest)
    assert any(
        ref.ref_id == "run-techvault-000" for ref in reconstructed.derived_from_refs
    )
