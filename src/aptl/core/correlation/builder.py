"""Correlation-graph builder (OBS-002, issue #447).

Builds a :class:`~aptl.core.correlation.models.CorrelationProjection` from
already-parsed APTL run-archive inputs — the ``aptl.run-record/v1`` manifest
(whose embedded ``RuntimeSnapshot`` carries participant episode/behavior
history and evaluator results) and the ACES orchestrator's
``orchestration/<addr>/{result.json,history.jsonl}`` files. Pure: no I/O,
no wall clock, no UUIDs, no process-random ordering dependence — see
:mod:`aptl.core.correlation.persistence` for the archive-reading/writing
boundary that feeds this module. The graph-assembly machinery lives in the
private :mod:`aptl.core.correlation._assemble` module and the named
``DECLARED_RULE`` vocabulary in :mod:`aptl.core.correlation.rules` (split out
to keep each module within the repo's per-file line budget).

Reality this module is built against (verified live against
``aces-sdl==0.23.1`` and the APTL adapters, not the aspirational ACES
archival contracts EXP-002/REP-001 do not yet wire in):

- Participant events are the *lightweight*
  ``ParticipantBehaviorHistoryEventModel`` (a single ``timestamp``, no
  ``occurred_at``/``recorded_at``/``ingested_at``/``clock_authority`` to
  read) — see :mod:`aptl.backends.aces_participant_actions`.
- ``run_id`` is threaded only into the ACES orchestrator adapter
  (:mod:`aptl.backends.aces_orchestrator`); its persisted
  ``WorkflowExecutionState.run_id`` is the *workflow's own* internal
  execution id (an opaque ``uuid4().hex`` minted by
  :class:`aptl.core.runtime.workflow_engine.WorkflowEngine`), never the
  APTL run id, and ``WorkflowHistoryEvent`` payloads do not carry the
  workflow address as a field at all. That is why an orchestration node
  binds to the run via a ``DECLARED_RULE`` edge (``RUN_PATH_BINDING``)
  rather than an ``EXPLICIT_IDENTIFIER`` one, while participant
  episodes/actions/evaluator results — all read from the *same*
  ``manifest.json`` document, which does carry an explicit top-level
  ``run_id`` field equal to the run identity — bind via
  ``EXPLICIT_IDENTIFIER``.
- No ACES archival contract (``ExperimentEvidenceRecordModel``,
  ``ParticipantAttributionEdgeModel``, ``ExperimentAugmentationDisclosureModel``,
  ...) is wired into APTL yet. A ``planned_trial_id``/plan ref and
  augmentation-disclosure refs are read from ``run_record`` on a
  best-effort basis (a handful of plausible key paths) and simply omitted
  when absent — never fabricated.
"""

from __future__ import annotations

from collections.abc import Mapping

from aptl.core.correlation._assemble import (
    _Accumulator,
    _add_actions,
    _add_behavior_evidence,
    _add_episodes,
    _add_evaluator_results,
    _add_external_evidence,
    _add_orchestration,
    _add_planned_trial,
    _add_run_node,
    _collect_action_ids,
    _collect_episode_ids,
    _find_disclosure_refs,
    _flatten_behavior_events,
    _map_action_to_episode,
    _map_action_to_events,
    _runtime_snapshot,
)
from aptl.core.correlation.clock import ClockProvider
from aptl.core.correlation.identity import bind_attempt_ref
from aptl.core.correlation.models import CorrelationProjection
from aptl.core.correlation.rules import (
    ADMITTED_PLAN_BINDING,
    DEFAULT_RULE_SET,
    ORCHESTRATION_ADDRESS_GROUPING,
    RUN_PATH_BINDING,
    CorrelationRule,
    CorrelationRuleSet,
)

__all__ = [
    "ADMITTED_PLAN_BINDING",
    "DEFAULT_RULE_SET",
    "ORCHESTRATION_ADDRESS_GROUPING",
    "RUN_PATH_BINDING",
    "CorrelationRule",
    "CorrelationRuleSet",
    "build_correlation_projection",
]


def build_correlation_projection(
    *,
    run_id: str,
    run_record: Mapping[str, object],
    orchestration: Mapping[str, Mapping[str, object]],
    clock_provider: ClockProvider,
    rules: CorrelationRuleSet | None = None,
) -> CorrelationProjection:
    """Build a :class:`CorrelationProjection` from already-parsed run-archive
    inputs. Pure and deterministic: the result depends only on the content
    of ``run_record``/``orchestration``, never on their input ordering, wall
    clock, or process-random state (:func:`ClockProvider.clock_context`
    supplies clock *disclosures* attached to candidate edges, never node/edge
    identity — see the module docstring for the exact reality this reads).
    """
    acc = _Accumulator(clock_provider=clock_provider, rules=rules or DEFAULT_RULE_SET)
    run_ref = bind_attempt_ref(run_id)
    _add_run_node(acc, run_ref)
    _add_planned_trial(acc, run_record, run_ref)

    runtime_snapshot = _runtime_snapshot(run_record)
    behavior_events = _flatten_behavior_events(runtime_snapshot)
    episode_ids = _collect_episode_ids(runtime_snapshot, behavior_events)
    action_ids = _collect_action_ids(behavior_events)
    action_to_episode = _map_action_to_episode(behavior_events)
    action_to_events = _map_action_to_events(behavior_events)

    _add_episodes(acc, episode_ids, run_ref)
    _add_actions(acc, action_ids, action_to_episode, run_ref)
    _add_behavior_evidence(acc, behavior_events)
    _add_orchestration(acc, orchestration, run_ref)
    _add_evaluator_results(acc, runtime_snapshot, run_ref, action_ids, action_to_events)
    _add_external_evidence(acc, run_record, run_ref)

    return CorrelationProjection(
        run_id=run_ref,
        nodes=tuple(acc.nodes.values()),
        edges=tuple(acc.edges),
        clock_contexts=tuple(acc.clock_contexts.values()),
        disclosures=_find_disclosure_refs(run_record),
    )
