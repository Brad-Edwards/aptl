"""Correlation-graph assembly for the OBS-002 builder (#447).

The mutable :class:`_Accumulator` plus one small section-builder per concern
(nodes/edges for the run, planned trial, participant episodes/actions, behavior
evidence, orchestration, evaluator results, external evidence). Split from the
public :mod:`aptl.core.correlation.builder` and the read-only
:mod:`aptl.core.correlation._extract` helpers to keep each module within the
per-file line budget (SonarCloud ``python:S104``). Not a public API.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from aptl.core.correlation._extract import (
    _derive_distinct_refs,
    _events_window,
    _evaluator_window,
    _external_evidence_references,
    _find_planned_trial_id,
    _participant_address_of,
    _windows_overlap,
)
from aptl.core.correlation.clock import ClockProvider
from aptl.core.correlation.identity import bind_attempt_ref, stable_ref
from aptl.core.correlation.models import (
    AssociationMethod,
    ClockContext,
    CorrelationEdge,
    CorrelationNode,
)
from aptl.core.correlation.rules import (
    ADMITTED_PLAN_BINDING,
    MANIFEST_SNAPSHOT_MEMBERSHIP,
    ORCHESTRATION_ADDRESS_GROUPING,
    RUN_PATH_BINDING,
    CorrelationRuleSet,
)

# Domain separation for content-derived refs (identity.stable_ref). Distinct
# per source category so a byte-identical dict from two different sources can
# never collide into the same node ref.
_BEHAVIOR_EVIDENCE_DOMAIN = b"aptl.correlation.builder.behavior-evidence/v1"
_ORCHESTRATION_EVIDENCE_DOMAIN = b"aptl.correlation.builder.orchestration-evidence/v1"
_EXTERNAL_EVIDENCE_DOMAIN = b"aptl.correlation.builder.external-evidence/v1"
_CLOCK_CONTEXT_REF_DOMAIN = b"aptl.correlation.builder.clock-context/v1"


@dataclass
class _Accumulator:
    """Mutable node/edge/clock-context collector for one projection build.

    Nodes/edges/clock-contexts are order-independent sets (the
    ``CorrelationProjection`` canonicalizes by sorting), so this only guards
    against a ref being redeclared under a conflicting ref_kind and caches one
    ClockContext per distinct source.
    """

    clock_provider: ClockProvider
    rules: CorrelationRuleSet
    nodes: dict[str, CorrelationNode] = field(default_factory=dict)
    edges: list[CorrelationEdge] = field(default_factory=list)
    clock_contexts: dict[tuple[str, str], ClockContext] = field(default_factory=dict)

    def add_node(self, ref: str, ref_kind: str) -> str:
        """Register ``ref`` as a node, rejecting a conflicting ref_kind for it."""
        existing = self.nodes.get(ref)
        if existing is not None and existing.ref_kind != ref_kind:
            raise ValueError(
                f"correlation ref {ref!r} redeclared with a conflicting "
                f"ref_kind ({existing.ref_kind!r} vs {ref_kind!r})"
            )
        self.nodes[ref] = CorrelationNode(ref=ref, ref_kind=ref_kind)
        return ref

    def add_edge(
        self,
        source_ref: str,
        target_ref: str,
        association_method: AssociationMethod,
        *,
        rule_id: str | None = None,
        clock_context_ref: str | None = None,
        confidence_or_status: str | None = None,
        disclosure_refs: tuple[str, ...] = (),
    ) -> None:
        """Append one typed correlation edge."""
        self.edges.append(
            CorrelationEdge(
                source_ref=source_ref,
                target_ref=target_ref,
                association_method=association_method,
                rule_id=rule_id,
                clock_context_ref=clock_context_ref,
                confidence_or_status=confidence_or_status,
                disclosure_refs=disclosure_refs,
            )
        )

    def clock_context_for(
        self, source_kind: str, source_id: str, *, observer_effect_ref: str | None = None
    ) -> ClockContext:
        """Return the (cached) ClockContext for this exact ``(source_kind,
        source_id)`` — one ClockContext per source, never merged across
        sources even when they share a provider."""
        key = (source_kind, source_id)
        ctx = self.clock_contexts.get(key)
        if ctx is None:
            ctx = self.clock_provider.clock_context(
                source_kind=source_kind, source_id=source_id, observer_effect_ref=observer_effect_ref
            )
            self.clock_contexts[key] = ctx
        return ctx

    @staticmethod
    def clock_ref(ctx: ClockContext) -> str:
        """Stable ref for a ClockContext (its ``clock_context_ref`` in edges)."""
        return stable_ref(
            ctx.source_kind, ctx.source_id, ctx.timestamp_domain, domain=_CLOCK_CONTEXT_REF_DOMAIN
        )

    def clock_ref_for(
        self, source_kind: str, source_id: str, *, observer_effect_ref: str | None = None
    ) -> str:
        """Record (if new) and return the clock ref for a ``(source_kind, source_id)``."""
        return self.clock_ref(
            self.clock_context_for(source_kind, source_id, observer_effect_ref=observer_effect_ref)
        )


def _add_run_node(acc: _Accumulator, run_ref: str) -> None:
    """Add the top-level attempt/run node."""
    acc.add_node(run_ref, "attempt-run")


def _add_planned_trial(acc: _Accumulator, run_record: Mapping[str, object], run_ref: str) -> None:
    """Add a planned-trial node bound to the run by the admitted-plan rule,
    when the run record carries a planned-trial id."""
    planned_trial_id = _find_planned_trial_id(run_record)
    if planned_trial_id is None:
        return
    planned_ref = bind_attempt_ref(planned_trial_id)
    acc.add_node(planned_ref, "planned-trial")
    acc.add_edge(
        planned_ref,
        run_ref,
        AssociationMethod.DECLARED_RULE,
        rule_id=acc.rules.require(ADMITTED_PLAN_BINDING.rule_id),
    )


def _add_episodes(acc: _Accumulator, episode_ids: set[str], run_ref: str) -> None:
    """Add participant-episode nodes, each bound to the run by manifest
    containment (the record carries no run_id of its own — DECLARED_RULE)."""
    for episode_id in episode_ids:
        episode_ref = bind_attempt_ref(episode_id)
        acc.add_node(episode_ref, "participant-episode")
        acc.add_edge(
            episode_ref,
            run_ref,
            AssociationMethod.DECLARED_RULE,
            rule_id=acc.rules.require(MANIFEST_SNAPSHOT_MEMBERSHIP.rule_id),
        )


def _add_actions(
    acc: _Accumulator,
    action_ids: set[str],
    action_to_episode: Mapping[str, str],
    run_ref: str,
) -> None:
    """Add action nodes: bound to the run by manifest containment
    (DECLARED_RULE), and to their episode by the shared episode id
    (EXPLICIT_IDENTIFIER) when known."""
    for action_id in action_ids:
        action_ref = bind_attempt_ref(action_id)
        acc.add_node(action_ref, "action")
        acc.add_edge(
            action_ref,
            run_ref,
            AssociationMethod.DECLARED_RULE,
            rule_id=acc.rules.require(MANIFEST_SNAPSHOT_MEMBERSHIP.rule_id),
        )
        episode_id = action_to_episode.get(action_id)
        if episode_id:
            acc.add_edge(
                action_ref, bind_attempt_ref(episode_id), AssociationMethod.EXPLICIT_IDENTIFIER
            )


def _add_behavior_evidence(acc: _Accumulator, behavior_events: Sequence[Mapping[str, object]]) -> None:
    """Add one evidence node per behavior event, explicitly linked to the
    action/episode ids the event itself carries, and record the participant
    clock when the event has a timestamp."""
    evidence_refs = _derive_distinct_refs(behavior_events, domain=_BEHAVIOR_EVIDENCE_DOMAIN)
    for event, evidence_ref in zip(behavior_events, evidence_refs, strict=True):
        acc.add_node(evidence_ref, "evidence")
        action_id = event.get("action_instance_id")
        if isinstance(action_id, str) and action_id:
            acc.add_edge(
                evidence_ref, bind_attempt_ref(action_id), AssociationMethod.EXPLICIT_IDENTIFIER
            )
        episode_id = event.get("episode_id")
        if isinstance(episode_id, str) and episode_id:
            acc.add_edge(
                evidence_ref, bind_attempt_ref(episode_id), AssociationMethod.EXPLICIT_IDENTIFIER
            )
        participant_address = event.get("participant_address")
        if isinstance(participant_address, str) and participant_address and event.get("timestamp"):
            acc.clock_ref_for("participant", participant_address)


def _add_orchestration_address(
    acc: _Accumulator, address: str, payload: Mapping[str, object], run_ref: str
) -> str:
    """Add an orchestration-address node bound to the run by the run-path rule
    (its own workflow run_id is a distinct, workflow-internal identity)."""
    address_ref = bind_attempt_ref(address)
    acc.add_node(address_ref, "action")
    acc.add_edge(
        address_ref,
        run_ref,
        AssociationMethod.DECLARED_RULE,
        rule_id=acc.rules.require(RUN_PATH_BINDING.rule_id),
    )
    result = payload.get("result")
    if isinstance(result, Mapping) and (result.get("started_at") or result.get("updated_at")):
        acc.clock_ref_for("orchestration", address)
    return address_ref


def _add_orchestration_history(
    acc: _Accumulator, address_ref: str, history: Sequence[Mapping[str, object]]
) -> None:
    """Add one evidence node per workflow history event, grouped under its
    address by the orchestration-address-grouping rule."""
    history_refs = _derive_distinct_refs(history, domain=_ORCHESTRATION_EVIDENCE_DOMAIN)
    for history_ref in history_refs:
        acc.add_node(history_ref, "evidence")
        acc.add_edge(
            history_ref,
            address_ref,
            AssociationMethod.DECLARED_RULE,
            rule_id=acc.rules.require(ORCHESTRATION_ADDRESS_GROUPING.rule_id),
        )


def _add_orchestration(
    acc: _Accumulator, orchestration: Mapping[str, Mapping[str, object]], run_ref: str
) -> None:
    """Add every orchestration address and its history events."""
    for address, payload in orchestration.items():
        if not isinstance(payload, Mapping):
            continue
        address_ref = _add_orchestration_address(acc, address, payload, run_ref)
        history = payload.get("history")
        if isinstance(history, list):
            events = [event for event in history if isinstance(event, Mapping)]
            _add_orchestration_history(acc, address_ref, events)


def _add_evaluator_result_candidates(
    acc: _Accumulator,
    address_ref: str,
    eval_window: tuple[datetime, datetime],
    eval_ctx: ClockContext,
    action_ids: set[str],
    action_to_events: Mapping[str, Sequence[Mapping[str, object]]],
) -> None:
    """Associate an evaluator result with actions, honestly reconciling both
    sources' clocks BEFORE claiming any temporal candidate.

    The evaluator and participant clocks are distinct sources. Their windows
    are only comparable when they share a timestamp domain: then an overlap is
    a ``TIME_WINDOW_CANDIDATE`` (never EXPLICIT/DECLARED — no ACES contract
    propagates a shared id across the evaluation/participant namespaces). When
    the domains differ and no offset reconciles them, overlap cannot be
    established, so the edge is an explicit ``GAP_OR_UNKNOWN`` disclosing the
    unreconciled clocks rather than a candidate that merely *looks*
    clock-qualified. Every emitted edge names BOTH clock inputs — the evaluator
    via ``clock_context_ref``, the participant via ``disclosure_refs`` — so the
    comparison basis is auditable.
    """
    eval_clock_ref = acc.clock_ref(eval_ctx)
    for action_id in action_ids:
        events = action_to_events.get(action_id, ())
        participant_address = _participant_address_of(events)
        if participant_address is None:
            continue
        part_ctx = acc.clock_context_for("participant", participant_address)
        part_clock_ref = acc.clock_ref(part_ctx)
        if part_ctx.timestamp_domain != eval_ctx.timestamp_domain:
            acc.add_edge(
                address_ref,
                bind_attempt_ref(action_id),
                AssociationMethod.GAP_OR_UNKNOWN,
                confidence_or_status="cross_domain_clock_unreconciled",
                disclosure_refs=(eval_clock_ref, part_clock_ref),
            )
            continue
        action_window = _events_window(events)
        if action_window is None or not _windows_overlap(eval_window, action_window):
            continue
        acc.add_edge(
            address_ref,
            bind_attempt_ref(action_id),
            AssociationMethod.TIME_WINDOW_CANDIDATE,
            clock_context_ref=eval_clock_ref,
            confidence_or_status="overlapping_window_reconciled_domain",
            disclosure_refs=(part_clock_ref,),
        )


def _add_evaluator_results(
    acc: _Accumulator,
    runtime_snapshot: Mapping[str, object],
    run_ref: str,
    action_ids: set[str],
    action_to_events: Mapping[str, Sequence[Mapping[str, object]]],
) -> None:
    """Add evaluator-result nodes (bound to the run by manifest containment)
    and their reconciled time-window candidate/gap edges to actions."""
    evaluation_results = runtime_snapshot.get("evaluation_results")
    if not isinstance(evaluation_results, Mapping):
        return
    for address, payload in evaluation_results.items():
        if not isinstance(payload, Mapping):
            continue
        address_ref = bind_attempt_ref(address)
        acc.add_node(address_ref, "evaluator-result")
        acc.add_edge(
            address_ref,
            run_ref,
            AssociationMethod.DECLARED_RULE,
            rule_id=acc.rules.require(MANIFEST_SNAPSHOT_MEMBERSHIP.rule_id),
        )
        eval_window = _evaluator_window(payload)
        if eval_window is None:
            continue
        eval_ctx = acc.clock_context_for("evaluator", address)
        _add_evaluator_result_candidates(
            acc, address_ref, eval_window, eval_ctx, action_ids, action_to_events
        )


def _add_external_evidence(acc: _Accumulator, run_record: Mapping[str, object], run_ref: str) -> None:
    """Add external evidence reference nodes. These carry no
    participant/episode/action/run identifier, so ``GAP_OR_UNKNOWN`` is the
    only honest association method (preflight: "no id propagation on the
    Python side")."""
    references = _external_evidence_references(run_record)
    refs = _derive_distinct_refs(references, domain=_EXTERNAL_EVIDENCE_DOMAIN)
    for evidence_ref in refs:
        acc.add_node(evidence_ref, "evidence")
        acc.add_edge(
            evidence_ref,
            run_ref,
            AssociationMethod.GAP_OR_UNKNOWN,
            confidence_or_status="no_propagated_identifier",
        )
