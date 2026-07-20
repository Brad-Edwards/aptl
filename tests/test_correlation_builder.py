"""Tests for ``aptl.core.correlation.builder`` (OBS-002 Stage 2, issue #447).

Fixtures mirror the REAL APTL run-archive shapes read from
``aptl.backends.aces_repro`` (the ``aptl.run-record/v1`` manifest and its
embedded ``RuntimeSnapshot``), ``aptl.backends.aces_participant_actions``
(``ParticipantBehaviorHistoryEventModel``-shaped behavior events), and
``aptl.backends.aces_orchestrator``/``aptl.core.runtime.workflow_engine``
(``WorkflowExecutionState``/``WorkflowHistoryEvent``-shaped orchestration
records) — not an invented local schema.

Covers: each of the four association methods produced in the right
circumstance; clock skew across distinct domains never collapsing into an
explicit/causal edge; a missing source timestamp recorded as an honest gap
rather than a fabricated candidate; duplicate (byte-identical) events kept
as distinct nodes; episode restarts preserved as distinct episode nodes;
reordered ingestion producing an identical projection; timestamp proximity
never yielding an EXPLICIT_IDENTIFIER edge; an end-to-end connected typed
path from an action through red/blue evidence to an evaluator result and
the run; and determinism (repeat build byte-identical, input-order
independent).
"""

from __future__ import annotations

import random

import pytest

from aptl.core.correlation.builder import (
    ADMITTED_PLAN_BINDING,
    ORCHESTRATION_ADDRESS_GROUPING,
    RUN_PATH_BINDING,
    CorrelationRuleSet,
    build_correlation_projection,
)
from aptl.core.correlation.clock import ClockProvider, FixedClockProvider
from aptl.core.correlation.identity import bind_attempt_ref
from aptl.core.correlation.models import AssociationMethod, ClockContext

# ---------------------------------------------------------------------------
# Fixture builders — shaped like the real ACES/APTL archive records.
# ---------------------------------------------------------------------------

_PARTICIPANT_ADDRESS = "participant.behavior.techvault.kali-victim-ssh-probe"
_ACTION_CONTRACT_ADDRESS = "participant.action-contract.aptl.kali-victim-ssh-probe"
_OBSERVATION_BOUNDARY_ADDRESS = "participant.observation-boundary.aptl.kali-victim-ssh-probe"


def _behavior_event(
    *,
    event_type: str,
    timestamp: str,
    participant_address: str = _PARTICIPANT_ADDRESS,
    episode_id: str,
    action_instance_id: str,
    **overrides: object,
) -> dict[str, object]:
    """Build a dict shaped like ``ParticipantBehaviorHistoryEventModel``
    (verified fields: ``aces_contracts.contracts.py:1433``)."""
    base: dict[str, object] = {
        "event_type": event_type,
        "timestamp": timestamp,
        "participant_address": participant_address,
        "episode_id": episode_id,
        "action_instance_id": action_instance_id,
        "action_contract_address": _ACTION_CONTRACT_ADDRESS,
        "observation_boundary_address": None,
        "observation_status": None,
        "actor_provenance": "codex-cli",
        "lifecycle_phase": None,
        "phase_realization": None,
        "admission_disposition": None,
        "operation_ref": None,
        "operation_state": None,
        "state_transition_kind": None,
        "post_state_digest": None,
        "joint_action_set_id": None,
        "realized_order": None,
        "interaction_ref": None,
        "interaction_class": "shared_state_change",
        "shared_state_refs": ["container:aptl-kali"],
        "details": {},
    }
    base.update(overrides)
    return base


def _attempted_and_observed(
    *, episode_id: str, action_instance_id: str, attempted_at: str, observed_at: str
) -> tuple[dict[str, object], dict[str, object]]:
    """One red-team-attempted / blue-observed event pair for one action —
    mirrors ``_action_attempted_event``/``_observation_event`` in
    ``aces_participant_actions.py``."""
    attempted = _behavior_event(
        event_type="action_attempted",
        timestamp=attempted_at,
        episode_id=episode_id,
        action_instance_id=action_instance_id,
        lifecycle_phase="execution_attempt",
        phase_realization="runtime_mediated",
        operation_ref="container_exec:aptl-kali",
        operation_state="running",
    )
    observed = _behavior_event(
        event_type="observation_emitted",
        timestamp=observed_at,
        episode_id=episode_id,
        action_instance_id=action_instance_id,
        observation_boundary_address=_OBSERVATION_BOUNDARY_ADDRESS,
        observation_status="terminal",
        lifecycle_phase="observation_emission",
        phase_realization="observed",
        post_state_digest="sha256:" + "a" * 64,
    )
    return attempted, observed


def _runtime_snapshot(
    *,
    behavior_history: dict[str, list[dict[str, object]]] | None = None,
    episode_results: dict[str, dict[str, object]] | None = None,
    episode_history: dict[str, list[dict[str, object]]] | None = None,
    evaluation_results: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a dict shaped like ``_snapshot_payload(RuntimeSnapshot)``
    (verified: ``aces_runtime.control_plane_store._snapshot_payload``)."""
    return {
        "participant_episode_results": episode_results or {},
        "participant_episode_history": episode_history or {},
        "participant_behavior_history": behavior_history or {},
        "evaluation_results": evaluation_results or {},
    }


def _manifest(
    *,
    run_id: str,
    runtime_snapshot: dict[str, object],
    evidence_references: list[dict[str, object]] | None = None,
    planned_trial_id: str | None = None,
    disclosure_refs: list[str] | None = None,
) -> dict[str, object]:
    """Build a dict shaped like the ``aptl.run-record/v1`` manifest
    (verified: ``aces_repro.build_reproducibility_record``)."""
    realization: dict[str, object] = {}
    if planned_trial_id is not None:
        realization["planned_trial_id"] = planned_trial_id
    if disclosure_refs is not None:
        realization["disclosure_refs"] = list(disclosure_refs)
    return {
        "schema_version": "aptl.run-record/v1",
        "run_id": run_id,
        "aces": {"runtime_snapshot": runtime_snapshot, "realization": realization},
        "backend_evidence": {"evidence_references": evidence_references or []},
    }


def _workflow_history_event(
    *, event_type: str, timestamp: str, **overrides: object
) -> dict[str, object]:
    """Build a dict shaped like ``WorkflowHistoryEvent.to_payload()``."""
    base: dict[str, object] = {
        "event_type": event_type,
        "timestamp": timestamp,
        "step_name": None,
        "branch_name": None,
        "join_step": None,
        "outcome": None,
        "details": {},
    }
    base.update(overrides)
    return base


def _orchestration_record(
    *,
    address: str,
    started_at: str,
    updated_at: str,
    history: list[dict[str, object]] | None = None,
    workflow_status: str = "succeeded",
) -> dict[str, object]:
    """Build a dict shaped like ``{"result": ..., "history": [...]}`` read
    from ``orchestration/<address>/{result.json,history.jsonl}``. The
    result's own ``run_id`` is a *workflow-internal* id
    (``WorkflowEngine.register_pending`` mints ``uuid4().hex``) —
    deliberately NOT the APTL run id, to catch a builder that naively
    trusts it."""
    return {
        "result": {
            "state_schema_version": "aces-workflow-state/v1",
            "workflow_status": workflow_status,
            "run_id": "workflow-internal-deadbeefdeadbeefdeadbeefdeadbeef",
            "started_at": started_at,
            "updated_at": updated_at,
            "terminal_reason": "completed" if workflow_status == "succeeded" else None,
            "compensation_status": "not_required",
            "compensation_started_at": None,
            "compensation_updated_at": None,
            "compensation_failures": [],
            "steps": {},
        },
        "history": history or [],
    }


def _edges_by_method(proj, method: AssociationMethod):
    return [e for e in proj.edges if e.association_method is method]


def _node_refs(proj) -> set[str]:
    return {n.ref for n in proj.nodes}


def _connected_component(proj, start_ref: str) -> set[str]:
    """Undirected reachability over the projection's edges, from `start_ref`."""
    adjacency: dict[str, set[str]] = {}
    for edge in proj.edges:
        adjacency.setdefault(edge.source_ref, set()).add(edge.target_ref)
        adjacency.setdefault(edge.target_ref, set()).add(edge.source_ref)
    visited = {start_ref}
    frontier = [start_ref]
    while frontier:
        current = frontier.pop()
        for neighbor in adjacency.get(current, ()):
            if neighbor not in visited:
                visited.add(neighbor)
                frontier.append(neighbor)
    return visited


# ---------------------------------------------------------------------------
# A minimal, complete, one-action run: shared across several tests.
# ---------------------------------------------------------------------------

_RUN_ID = "run-e2e-1"
_EPISODE_ID = "episode-e2e-1"
_ACTION_ID = "participant.behavior.techvault.kali-victim-ssh-probe.aaaa1111"


def _minimal_run(**evaluation_kwargs) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    attempted, observed = _attempted_and_observed(
        episode_id=_EPISODE_ID,
        action_instance_id=_ACTION_ID,
        attempted_at="2026-01-01T00:00:00Z",
        observed_at="2026-01-01T00:00:05Z",
    )
    evaluation_results = evaluation_kwargs.get("evaluation_results")
    if evaluation_results is None:
        evaluation_results = {
            "evaluation.objective.techvault.foothold": {
                "outcome": "succeeded",
                "started_at": "2026-01-01T00:00:01Z",
                "updated_at": "2026-01-01T00:00:06Z",
            }
        }
    snapshot = _runtime_snapshot(
        behavior_history={_PARTICIPANT_ADDRESS: [attempted, observed]},
        episode_results={
            _PARTICIPANT_ADDRESS: {"episode_id": _EPISODE_ID, "status": "running"}
        },
        evaluation_results=evaluation_results,
    )
    manifest = _manifest(run_id=_RUN_ID, runtime_snapshot=snapshot)
    orchestration = _orchestration_record(
        address="runtime_apply_orchestration",
        started_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:02Z",
        history=[
            _workflow_history_event(event_type="workflow_started", timestamp="2026-01-01T00:00:00Z"),
            _workflow_history_event(event_type="workflow_completed", timestamp="2026-01-01T00:00:02Z"),
        ],
    )
    return manifest, {"runtime_apply_orchestration": orchestration}


def _build(manifest, orchestration, *, clock_provider=None, rules=None):
    return build_correlation_projection(
        run_id=_RUN_ID,
        run_record=manifest,
        orchestration=orchestration,
        clock_provider=clock_provider or FixedClockProvider(measurement_time="2026-01-01T00:10:00Z"),
        rules=rules,
    )


# ---------------------------------------------------------------------------
# CorrelationRuleSet
# ---------------------------------------------------------------------------


class TestCorrelationRuleSet:
    def test_default_rule_set_declares_the_named_rules(self):
        ruleset = CorrelationRuleSet()
        assert ruleset.require(RUN_PATH_BINDING.rule_id) == "run-path-binding"
        assert ruleset.require(ADMITTED_PLAN_BINDING.rule_id) == "admitted-plan-binding"
        assert ruleset.require(ORCHESTRATION_ADDRESS_GROUPING.rule_id) == "orchestration-address-grouping"

    def test_require_rejects_an_undeclared_rule_id(self):
        ruleset = CorrelationRuleSet()
        with pytest.raises(ValueError, match="undeclared"):
            ruleset.require("free-form-not-a-real-rule")

    def test_rejects_duplicate_rule_ids(self):
        from aptl.core.correlation.builder import CorrelationRule

        with pytest.raises(ValueError, match="unique"):
            CorrelationRuleSet(
                rules=(
                    CorrelationRule(rule_id="dup", description="a"),
                    CorrelationRule(rule_id="dup", description="b"),
                )
            )


# ---------------------------------------------------------------------------
# The four association methods, each in its documented circumstance.
# ---------------------------------------------------------------------------


class TestAssociationMethods:
    def test_explicit_identifier_links_action_to_episode_via_shared_episode_id(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        action_ref = bind_attempt_ref(_ACTION_ID)
        episode_ref = bind_attempt_ref(_EPISODE_ID)
        explicit = _edges_by_method(proj, AssociationMethod.EXPLICIT_IDENTIFIER)
        assert any(e.source_ref == action_ref and e.target_ref == episode_ref for e in explicit)

    def test_declared_rule_binds_manifest_scoped_nodes_to_run_not_explicit_identity(self):
        """Episode/action/evaluator-result records carry NO run_id field of
        their own — they belong to the run only because they were read from
        the RuntimeSnapshot embedded in that run's manifest.json. That is a
        declared containment rule (the same honest provenance orchestration
        files get), NEVER an EXPLICIT_IDENTIFIER: the record has no shared
        literal identifier to point at."""
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        run_ref = bind_attempt_ref(_RUN_ID)
        episode_ref = bind_attempt_ref(_EPISODE_ID)
        action_ref = bind_attempt_ref(_ACTION_ID)
        eval_ref = bind_attempt_ref("evaluation.objective.techvault.foothold")
        declared = {
            (e.source_ref, e.target_ref): e
            for e in _edges_by_method(proj, AssociationMethod.DECLARED_RULE)
        }
        explicit_targets = {
            (e.source_ref, e.target_ref)
            for e in _edges_by_method(proj, AssociationMethod.EXPLICIT_IDENTIFIER)
        }
        for src in (episode_ref, action_ref, eval_ref):
            assert (src, run_ref) in declared
            assert declared[(src, run_ref)].rule_id == "manifest-snapshot-membership"
            assert (src, run_ref) not in explicit_targets

    def test_declared_rule_links_orchestration_address_to_run_not_via_its_own_run_id_field(self):
        """The orchestration result's own `run_id` field is a DIFFERENT,
        workflow-internal identity (see `_orchestration_record`), so this
        can only be a DECLARED_RULE (archive-layout convention), never an
        EXPLICIT_IDENTIFIER."""
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        run_ref = bind_attempt_ref(_RUN_ID)
        address_ref = bind_attempt_ref("runtime_apply_orchestration")
        declared = _edges_by_method(proj, AssociationMethod.DECLARED_RULE)
        matches = [e for e in declared if e.source_ref == address_ref and e.target_ref == run_ref]
        assert len(matches) == 1
        assert matches[0].rule_id == "run-path-binding"
        # And it must NOT also appear as an EXPLICIT_IDENTIFIER edge.
        explicit = _edges_by_method(proj, AssociationMethod.EXPLICIT_IDENTIFIER)
        assert not any(e.source_ref == address_ref and e.target_ref == run_ref for e in explicit)

    def test_declared_rule_links_orchestration_history_events_to_their_address(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        address_ref = bind_attempt_ref("runtime_apply_orchestration")
        declared = _edges_by_method(proj, AssociationMethod.DECLARED_RULE)
        history_edges = [e for e in declared if e.target_ref == address_ref]
        assert len(history_edges) == 2  # workflow_started + workflow_completed
        assert all(e.rule_id == "orchestration-address-grouping" for e in history_edges)

    def test_declared_rule_links_planned_trial_to_run_when_present(self):
        manifest, orchestration = _minimal_run()
        manifest["aces"]["realization"]["planned_trial_id"] = "planned-trial-1"
        proj = _build(manifest, orchestration)
        run_ref = bind_attempt_ref(_RUN_ID)
        planned_ref = bind_attempt_ref("planned-trial-1")
        declared = _edges_by_method(proj, AssociationMethod.DECLARED_RULE)
        matches = [e for e in declared if e.source_ref == planned_ref and e.target_ref == run_ref]
        assert len(matches) == 1
        assert matches[0].rule_id == "admitted-plan-binding"
        assert any(n.ref == planned_ref and n.ref_kind == "planned-trial" for n in proj.nodes)

    def test_no_planned_trial_node_when_absent_from_the_run_record(self):
        """EXP-002/REP-001 do not thread planned_trial_id into the run
        record today (verified reality) — absence must not fabricate one."""
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        assert not any(n.ref_kind == "planned-trial" for n in proj.nodes)

    def test_time_window_candidate_links_overlapping_evaluator_result_to_action(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        eval_ref = bind_attempt_ref("evaluation.objective.techvault.foothold")
        action_ref = bind_attempt_ref(_ACTION_ID)
        candidates = _edges_by_method(proj, AssociationMethod.TIME_WINDOW_CANDIDATE)
        matches = [e for e in candidates if e.source_ref == eval_ref and e.target_ref == action_ref]
        assert len(matches) == 1
        assert matches[0].clock_context_ref is not None

    def test_time_window_candidate_is_absent_when_windows_do_not_overlap(self):
        manifest, orchestration = _minimal_run(
            evaluation_results={
                "evaluation.objective.techvault.foothold": {
                    "outcome": "succeeded",
                    "started_at": "2030-01-01T00:00:00Z",
                    "updated_at": "2030-01-01T00:00:01Z",
                }
            }
        )
        proj = _build(manifest, orchestration)
        candidates = _edges_by_method(proj, AssociationMethod.TIME_WINDOW_CANDIDATE)
        assert candidates == []

    def test_gap_or_unknown_links_external_evidence_reference_with_no_propagated_id(self):
        manifest, orchestration = _minimal_run()
        manifest["backend_evidence"]["evidence_references"] = [
            {"kind": "pcap", "path": "captures/eth0.pcap"}
        ]
        proj = _build(manifest, orchestration)
        run_ref = bind_attempt_ref(_RUN_ID)
        gaps = _edges_by_method(proj, AssociationMethod.GAP_OR_UNKNOWN)
        assert len(gaps) == 1
        assert gaps[0].target_ref == run_ref
        gap_node = next(n for n in proj.nodes if n.ref == gaps[0].source_ref)
        assert gap_node.ref_kind == "evidence"

    def test_timestamp_proximity_never_yields_an_explicit_identifier_edge(self):
        """The evaluator-result <-> action link is time-window-only in
        current APTL reality (no shared id field between the two
        namespaces) — even though their windows overlap, it must never be
        promoted to EXPLICIT_IDENTIFIER or DECLARED_RULE."""
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        eval_ref = bind_attempt_ref("evaluation.objective.techvault.foothold")
        action_ref = bind_attempt_ref(_ACTION_ID)
        for method in (AssociationMethod.EXPLICIT_IDENTIFIER, AssociationMethod.DECLARED_RULE):
            edges = _edges_by_method(proj, method)
            assert not any(e.source_ref == eval_ref and e.target_ref == action_ref for e in edges)


# ---------------------------------------------------------------------------
# Clock contexts / clock skew.
# ---------------------------------------------------------------------------


class _SkewClockProvider(ClockProvider):
    """Test-only provider: distinct clock_source/timestamp_domain/offset
    per source_kind, so distinct sources never collapse into one clock
    domain (preflight: "Different sources = DIFFERENT domains")."""

    _PROFILES = {
        "participant": ("host-utc", "system", None, None),
        "evaluator": ("evaluator-utc", "evaluator-process-clock", "+120ms", "50ms"),
        "orchestration": ("workflow-engine-utc", "workflow-engine-clock", "-50ms", "20ms"),
    }

    def now(self) -> str:
        return "2026-01-01T00:10:00Z"

    def clock_context(self, *, source_kind, source_id, observer_effect_ref=None):
        domain, source, offset, uncertainty = self._PROFILES.get(
            source_kind, ("host-utc", "system", None, None)
        )
        return ClockContext(
            source_kind=source_kind,
            source_id=source_id,
            timestamp_domain=domain,
            clock_source=source,
            synchronization_status="unknown",
            measured_offset=offset,
            uncertainty=uncertainty,
            measurement_time=self.now(),
            observer_effect_ref=observer_effect_ref,
        )


class TestClockHandling:
    def test_distinct_sources_record_distinct_clock_domains_and_offsets(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration, clock_provider=_SkewClockProvider())
        by_kind = {ctx.source_kind: ctx for ctx in proj.clock_contexts}
        assert by_kind["participant"].timestamp_domain == "host-utc"
        assert by_kind["participant"].measured_offset is None
        assert by_kind["evaluator"].timestamp_domain == "evaluator-utc"
        assert by_kind["evaluator"].measured_offset == "+120ms"
        assert by_kind["orchestration"].timestamp_domain == "workflow-engine-utc"
        assert by_kind["orchestration"].measured_offset == "-50ms"

    def test_skewed_clock_contexts_are_never_used_for_explicit_or_declared_edges(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration, clock_provider=_SkewClockProvider())
        for method in (AssociationMethod.EXPLICIT_IDENTIFIER, AssociationMethod.DECLARED_RULE):
            for edge in _edges_by_method(proj, method):
                assert edge.clock_context_ref is None

    def test_only_time_window_candidate_edges_carry_a_clock_context_ref(self):
        # Same-domain clocks (default provider) → the evaluator/action windows
        # are reconcilable, so an overlap is a real TIME_WINDOW_CANDIDATE that
        # carries a clock_context_ref; no other method carries one.
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        candidates = _edges_by_method(proj, AssociationMethod.TIME_WINDOW_CANDIDATE)
        assert candidates
        assert all(e.clock_context_ref is not None for e in candidates)
        for method in (
            AssociationMethod.EXPLICIT_IDENTIFIER,
            AssociationMethod.DECLARED_RULE,
            AssociationMethod.GAP_OR_UNKNOWN,
        ):
            assert all(e.clock_context_ref is None for e in _edges_by_method(proj, method))

    def test_cross_domain_evaluator_action_comparison_is_a_disclosed_gap_not_a_candidate(self):
        """OBS-002 clock reconciliation: timestamps from DIFFERENT clock
        domains cannot be compared for overlap without a known offset, so a
        skewed evaluator/participant pair yields an explicit GAP_OR_UNKNOWN
        that discloses BOTH clock inputs — never a clock-qualified-looking
        TIME_WINDOW_CANDIDATE built on an unreconciled comparison."""
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration, clock_provider=_SkewClockProvider())
        eval_ref = bind_attempt_ref("evaluation.objective.techvault.foothold")
        action_ref = bind_attempt_ref(_ACTION_ID)
        candidates = _edges_by_method(proj, AssociationMethod.TIME_WINDOW_CANDIDATE)
        assert not any(e.source_ref == eval_ref and e.target_ref == action_ref for e in candidates)
        gaps = [
            e
            for e in _edges_by_method(proj, AssociationMethod.GAP_OR_UNKNOWN)
            if e.source_ref == eval_ref and e.target_ref == action_ref
        ]
        assert len(gaps) == 1
        assert gaps[0].confidence_or_status == "cross_domain_clock_unreconciled"
        assert gaps[0].clock_context_ref is None
        # Both clock inputs (evaluator + participant) are named for audit.
        assert len(gaps[0].disclosure_refs) == 2

    def test_participant_clock_context_is_recorded_honestly_as_unknown_sync(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        participant_ctx = next(c for c in proj.clock_contexts if c.source_kind == "participant")
        assert participant_ctx.synchronization_status == "unknown"
        assert participant_ctx.measured_offset is None


# ---------------------------------------------------------------------------
# Missing source timestamps.
# ---------------------------------------------------------------------------


class TestMissingSourceTimestamp:
    def test_evaluator_result_without_any_timestamp_gets_no_fabricated_candidate_edge(self):
        manifest, orchestration = _minimal_run(
            evaluation_results={
                "evaluation.objective.techvault.foothold": {"outcome": "succeeded"}
            }
        )
        proj = _build(manifest, orchestration)
        eval_ref = bind_attempt_ref("evaluation.objective.techvault.foothold")
        candidates = _edges_by_method(proj, AssociationMethod.TIME_WINDOW_CANDIDATE)
        assert not any(e.source_ref == eval_ref for e in candidates)
        # It is still a real node, still bound to the run by manifest
        # containment: a missing timestamp is a time-correlation gap, not a
        # missing node.
        assert eval_ref in _node_refs(proj)
        run_ref = bind_attempt_ref(_RUN_ID)
        declared = _edges_by_method(proj, AssociationMethod.DECLARED_RULE)
        assert any(
            e.source_ref == eval_ref
            and e.target_ref == run_ref
            and e.rule_id == "manifest-snapshot-membership"
            for e in declared
        )

    def test_orchestration_result_without_timestamps_does_not_crash_and_records_no_clock_context(self):
        manifest, orchestration = _minimal_run()
        orchestration["runtime_apply_orchestration"]["result"]["started_at"] = ""
        orchestration["runtime_apply_orchestration"]["result"]["updated_at"] = ""
        proj = _build(manifest, orchestration)
        assert not any(c.source_kind == "orchestration" for c in proj.clock_contexts)
        # The address node and its DECLARED_RULE binding to run must still exist.
        address_ref = bind_attempt_ref("runtime_apply_orchestration")
        assert address_ref in _node_refs(proj)


# ---------------------------------------------------------------------------
# Duplicate events.
# ---------------------------------------------------------------------------


class TestDuplicateEvents:
    def test_two_byte_identical_attempted_events_produce_two_distinct_evidence_nodes(self):
        attempted, observed = _attempted_and_observed(
            episode_id=_EPISODE_ID,
            action_instance_id=_ACTION_ID,
            attempted_at="2026-01-01T00:00:00Z",
            observed_at="2026-01-01T00:00:05Z",
        )
        # A byte-identical duplicate of `attempted` (e.g. a retried emission).
        duplicate_attempted = dict(attempted)
        snapshot = _runtime_snapshot(
            behavior_history={_PARTICIPANT_ADDRESS: [attempted, duplicate_attempted, observed]},
        )
        manifest = _manifest(run_id=_RUN_ID, runtime_snapshot=snapshot)
        proj = _build(manifest, {})
        evidence_nodes = [n for n in proj.nodes if n.ref_kind == "evidence"]
        # 2 distinct attempted-event nodes + 1 observed-event node = 3.
        assert len(evidence_nodes) == 3
        assert len({n.ref for n in evidence_nodes}) == 3

    def test_duplicate_events_are_not_collapsed_regardless_of_which_copy_appears_first(self):
        attempted, observed = _attempted_and_observed(
            episode_id=_EPISODE_ID,
            action_instance_id=_ACTION_ID,
            attempted_at="2026-01-01T00:00:00Z",
            observed_at="2026-01-01T00:00:05Z",
        )
        duplicate_attempted = dict(attempted)
        forward = _runtime_snapshot(
            behavior_history={_PARTICIPANT_ADDRESS: [attempted, duplicate_attempted, observed]}
        )
        backward = _runtime_snapshot(
            behavior_history={_PARTICIPANT_ADDRESS: [duplicate_attempted, attempted, observed]}
        )
        proj_forward = _build(_manifest(run_id=_RUN_ID, runtime_snapshot=forward), {})
        proj_backward = _build(_manifest(run_id=_RUN_ID, runtime_snapshot=backward), {})
        assert proj_forward.projection_digest == proj_backward.projection_digest


# ---------------------------------------------------------------------------
# Restarts.
# ---------------------------------------------------------------------------


class TestRestarts:
    def test_a_restarted_episode_produces_two_distinct_episode_nodes(self):
        episode_1 = "episode-restart-1"
        episode_2 = "episode-restart-2"
        action_1 = "participant.behavior.techvault.kali-victim-ssh-probe.1111"
        action_2 = "participant.behavior.techvault.kali-victim-ssh-probe.2222"
        attempted_1, observed_1 = _attempted_and_observed(
            episode_id=episode_1,
            action_instance_id=action_1,
            attempted_at="2026-01-01T00:00:00Z",
            observed_at="2026-01-01T00:00:05Z",
        )
        attempted_2, observed_2 = _attempted_and_observed(
            episode_id=episode_2,
            action_instance_id=action_2,
            attempted_at="2026-01-01T00:01:00Z",
            observed_at="2026-01-01T00:01:05Z",
        )
        snapshot = _runtime_snapshot(
            behavior_history={
                _PARTICIPANT_ADDRESS: [attempted_1, observed_1, attempted_2, observed_2]
            },
            episode_results={
                # Only the LATEST episode survives in participant_episode_results
                # (a single envelope per address) — restarts are only visible
                # through the behavior history's own episode_id fields.
                _PARTICIPANT_ADDRESS: {
                    "episode_id": episode_2,
                    "previous_episode_id": episode_1,
                    "status": "running",
                }
            },
        )
        manifest = _manifest(run_id=_RUN_ID, runtime_snapshot=snapshot)
        proj = _build(manifest, {})
        episode_refs = {n.ref for n in proj.nodes if n.ref_kind == "participant-episode"}
        assert episode_refs == {bind_attempt_ref(episode_1), bind_attempt_ref(episode_2)}
        # Each action still binds to its OWN episode, never merged.
        explicit = _edges_by_method(proj, AssociationMethod.EXPLICIT_IDENTIFIER)
        assert (bind_attempt_ref(action_1), bind_attempt_ref(episode_1)) in {
            (e.source_ref, e.target_ref) for e in explicit
        }
        assert (bind_attempt_ref(action_2), bind_attempt_ref(episode_2)) in {
            (e.source_ref, e.target_ref) for e in explicit
        }


# ---------------------------------------------------------------------------
# Reordered ingestion.
# ---------------------------------------------------------------------------


class TestReorderedIngestion:
    def test_reordering_the_behavior_event_list_does_not_change_the_digest(self):
        manifest, orchestration = _minimal_run()
        events = manifest["aces"]["runtime_snapshot"]["participant_behavior_history"][
            _PARTICIPANT_ADDRESS
        ]
        proj_forward = _build(manifest, orchestration)
        reversed_manifest = _manifest(
            run_id=_RUN_ID,
            runtime_snapshot=_runtime_snapshot(
                behavior_history={_PARTICIPANT_ADDRESS: list(reversed(events))},
                episode_results=manifest["aces"]["runtime_snapshot"]["participant_episode_results"],
                evaluation_results=manifest["aces"]["runtime_snapshot"]["evaluation_results"],
            ),
        )
        proj_backward = _build(reversed_manifest, orchestration)
        assert proj_forward.projection_digest == proj_backward.projection_digest

    def test_reordering_the_orchestration_address_dict_does_not_change_the_digest(self):
        manifest, _ = _minimal_run()
        orch_a = _orchestration_record(
            address="address-a", started_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:01Z"
        )
        orch_b = _orchestration_record(
            address="address-b", started_at="2026-01-01T00:00:02Z", updated_at="2026-01-01T00:00:03Z"
        )
        forward = {"address-a": orch_a, "address-b": orch_b}
        backward = {"address-b": orch_b, "address-a": orch_a}
        proj_forward = _build(manifest, forward)
        proj_backward = _build(manifest, backward)
        assert proj_forward.projection_digest == proj_backward.projection_digest

    def test_reordering_orchestration_history_events_does_not_change_the_digest(self):
        manifest, _ = _minimal_run()
        events = [
            _workflow_history_event(event_type="workflow_started", timestamp="2026-01-01T00:00:00Z"),
            _workflow_history_event(event_type="step_started", timestamp="2026-01-01T00:00:01Z", step_name="s1"),
            _workflow_history_event(event_type="workflow_completed", timestamp="2026-01-01T00:00:02Z"),
        ]
        forward = {
            "runtime_apply_orchestration": _orchestration_record(
                address="runtime_apply_orchestration",
                started_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:02Z",
                history=events,
            )
        }
        backward = {
            "runtime_apply_orchestration": _orchestration_record(
                address="runtime_apply_orchestration",
                started_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:02Z",
                history=list(reversed(events)),
            )
        }
        proj_forward = _build(manifest, forward)
        proj_backward = _build(manifest, backward)
        assert proj_forward.projection_digest == proj_backward.projection_digest


# ---------------------------------------------------------------------------
# End-to-end connected typed path.
# ---------------------------------------------------------------------------


class TestEndToEndTrace:
    def test_action_red_evidence_blue_observation_evaluator_result_and_run_are_connected(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)

        action_ref = bind_attempt_ref(_ACTION_ID)
        run_ref = bind_attempt_ref(_RUN_ID)
        eval_ref = bind_attempt_ref("evaluation.objective.techvault.foothold")

        # The two behavior-history evidence nodes (red attempted / blue
        # observed) both derive from content, so look them up by ref_kind
        # + edge participation instead of a literal id.
        evidence_refs = {
            e.source_ref
            for e in proj.edges
            if e.association_method is AssociationMethod.EXPLICIT_IDENTIFIER and e.target_ref == action_ref
        }
        assert len(evidence_refs) == 2  # attempted + observed

        component = _connected_component(proj, run_ref)
        assert action_ref in component
        assert eval_ref in component
        for evidence_ref in evidence_refs:
            assert evidence_ref in component

    def test_typed_path_uses_only_documented_association_methods(self):
        manifest, orchestration = _minimal_run()
        proj = _build(manifest, orchestration)
        methods = {e.association_method for e in proj.edges}
        assert methods <= set(AssociationMethod)
        assert AssociationMethod.EXPLICIT_IDENTIFIER in methods
        assert AssociationMethod.DECLARED_RULE in methods
        assert AssociationMethod.TIME_WINDOW_CANDIDATE in methods


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_build_is_byte_identical(self):
        manifest, orchestration = _minimal_run()
        proj1 = _build(manifest, orchestration)
        proj2 = _build(manifest, orchestration)
        assert proj1.canonical_bytes == proj2.canonical_bytes
        assert proj1.projection_digest == proj2.projection_digest

    def test_digest_is_independent_of_manifest_dict_key_order(self):
        manifest, orchestration = _minimal_run()
        reordered = dict(reversed(list(manifest.items())))
        proj1 = _build(manifest, orchestration)
        proj2 = _build(reordered, orchestration)
        assert proj1.projection_digest == proj2.projection_digest

    def test_build_never_uses_wall_clock_for_node_or_edge_identity(self):
        """Two builds against two DIFFERENT clock_provider `now()` values
        (only used for candidate-edge clock disclosures, never identity)
        must still produce identical node/edge sets."""
        manifest, orchestration = _minimal_run()
        proj_a = _build(
            manifest, orchestration, clock_provider=FixedClockProvider(measurement_time="2026-01-01T00:00:00Z")
        )
        proj_b = _build(
            manifest, orchestration, clock_provider=FixedClockProvider(measurement_time="2099-12-31T23:59:59Z")
        )
        assert {n.ref for n in proj_a.nodes} == {n.ref for n in proj_b.nodes}
        assert {(e.source_ref, e.target_ref, e.association_method) for e in proj_a.edges} == {
            (e.source_ref, e.target_ref, e.association_method) for e in proj_b.edges
        }


# ---------------------------------------------------------------------------
# Fuzz (property-based) — determinism / order-independence.
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
class TestFuzzOrderIndependence:
    @given(seed=st.integers(min_value=0, max_value=2**31 - 1))
    @settings(max_examples=25, deadline=None)
    def test_shuffled_behavior_events_and_orchestration_addresses_preserve_digest(self, seed):
        rng = random.Random(seed)
        manifest, orchestration = _minimal_run()
        events = list(
            manifest["aces"]["runtime_snapshot"]["participant_behavior_history"][_PARTICIPANT_ADDRESS]
        )
        shuffled_events = list(events)
        rng.shuffle(shuffled_events)
        shuffled_manifest = _manifest(
            run_id=_RUN_ID,
            runtime_snapshot=_runtime_snapshot(
                behavior_history={_PARTICIPANT_ADDRESS: shuffled_events},
                episode_results=manifest["aces"]["runtime_snapshot"]["participant_episode_results"],
                evaluation_results=manifest["aces"]["runtime_snapshot"]["evaluation_results"],
            ),
        )
        baseline = _build(manifest, orchestration)
        shuffled = _build(shuffled_manifest, orchestration)
        assert baseline.projection_digest == shuffled.projection_digest

    @given(seed=st.integers(min_value=0, max_value=2**31 - 1))
    @settings(max_examples=25, deadline=None)
    def test_repeated_build_is_always_byte_identical(self, seed):
        manifest, orchestration = _minimal_run()
        first = _build(manifest, orchestration)
        second = _build(manifest, orchestration)
        assert first.canonical_bytes == second.canonical_bytes
