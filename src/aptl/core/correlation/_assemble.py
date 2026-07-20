"""Internal graph-assembly helpers for the OBS-002 correlation builder (#447).

Split out of :mod:`aptl.core.correlation.builder` to keep each module within
the repo's per-file line budget (SonarCloud ``python:S104``). Not a public
API — the only supported entry point is
:func:`aptl.core.correlation.builder.build_correlation_projection`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

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

# ---------------------------------------------------------------------------
# Domain separation for content-derived refs (identity.stable_ref). Distinct
# per source category so a byte-identical dict from two different sources
# (e.g. a behavior event and an orchestration history event that happen to
# serialize the same way) can never collide into the same node ref.
# ---------------------------------------------------------------------------

_BEHAVIOR_EVIDENCE_DOMAIN = b"aptl.correlation.builder.behavior-evidence/v1"
_ORCHESTRATION_EVIDENCE_DOMAIN = b"aptl.correlation.builder.orchestration-evidence/v1"
_EXTERNAL_EVIDENCE_DOMAIN = b"aptl.correlation.builder.external-evidence/v1"
_CLOCK_CONTEXT_REF_DOMAIN = b"aptl.correlation.builder.clock-context/v1"


# ---------------------------------------------------------------------------
# Content-derived, order-independent, duplicate-preserving refs.
# ---------------------------------------------------------------------------


def _content_signature(payload: object) -> str:
    """Canonical string signature for grouping byte-identical raw dicts.

    Sorted keys make signature independent of a dict's own key order;
    list *values* are left as-is because their order is meaningful
    source content (e.g. ``shared_state_refs``), not incidental
    ingestion order.
    """
    return json.dumps(payload, sort_keys=True, default=str)


def _derive_distinct_refs(items: Sequence[object], *, domain: bytes) -> list[str]:
    """Return one ref per item, positionally aligned with ``items``.

    Each ref is derived from the item's own content plus how many
    *identical* items were already counted (an occurrence index within
    the content-keyed multiset) — never from list position. Re-ordering
    ``items`` (simulating reordered ingestion) therefore produces the
    identical *set* of refs, while two genuinely duplicate (byte-for-byte
    identical) items still resolve to two distinct refs rather than
    collapsing into one (preflight: "Do not collapse duplicate events ...
    into one 'best' event").
    """
    occurrence_counts: dict[str, int] = {}
    refs: list[str] = []
    for item in items:
        signature = _content_signature(item)
        occurrence = occurrence_counts.get(signature, 0)
        occurrence_counts[signature] = occurrence + 1
        refs.append(stable_ref(signature, str(occurrence), domain=domain))
    return refs


# ---------------------------------------------------------------------------
# Timestamp parsing / window overlap (never used to assert an explicit or
# declared edge — only ever to justify a TIME_WINDOW_CANDIDATE, and always
# paired with a clock_context_ref).
# ---------------------------------------------------------------------------


def _parse_rfc3339(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _events_window(events: Sequence[Mapping[str, object]]) -> tuple[datetime, datetime] | None:
    """Return ``(earliest, latest)`` parsed timestamps among ``events``, or
    ``None`` when none of them carry a parseable timestamp (a missing
    source timestamp is a gap, never fabricated)."""
    timestamps = [ts for ts in (_parse_rfc3339(e.get("timestamp")) for e in events) if ts is not None]
    if not timestamps:
        return None
    return min(timestamps), max(timestamps)


def _evaluator_window(payload: Mapping[str, object]) -> tuple[datetime, datetime] | None:
    started = _parse_rfc3339(payload.get("started_at"))
    updated = _parse_rfc3339(payload.get("updated_at"))
    if started is None and updated is None:
        return None
    started = started if started is not None else updated
    updated = updated if updated is not None else started
    assert started is not None and updated is not None  # narrowed above
    return (started, updated) if started <= updated else (updated, started)


def _windows_overlap(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


# ---------------------------------------------------------------------------
# Run-record extraction helpers (best-effort: EXP-002/REP-001 do not thread
# planned_trial_id or augmentation disclosures into the run record today —
# these read a handful of plausible paths and are silently absent, never
# fabricated, when the field truly is not there).
# ---------------------------------------------------------------------------


def _runtime_snapshot(run_record: Mapping[str, object]) -> Mapping[str, object]:
    aces_section = run_record.get("aces")
    if not isinstance(aces_section, Mapping):
        return {}
    snapshot = aces_section.get("runtime_snapshot")
    return snapshot if isinstance(snapshot, Mapping) else {}


def _find_planned_trial_id(run_record: Mapping[str, object]) -> str | None:
    candidates: list[object] = [run_record.get("planned_trial_id")]
    aces_section = run_record.get("aces")
    if isinstance(aces_section, Mapping):
        candidates.append(aces_section.get("planned_trial_id"))
        realization = aces_section.get("realization")
        if isinstance(realization, Mapping):
            candidates.append(realization.get("planned_trial_id"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _find_disclosure_refs(run_record: Mapping[str, object]) -> tuple[str, ...]:
    aces_section = run_record.get("aces")
    if not isinstance(aces_section, Mapping):
        return ()
    realization = aces_section.get("realization")
    if not isinstance(realization, Mapping):
        return ()
    for key in ("disclosure_refs", "augmentation_disclosure_refs"):
        raw = realization.get(key)
        if isinstance(raw, list) and raw:
            return tuple(str(item) for item in raw if isinstance(item, str) and item)
    return ()


def _external_evidence_references(run_record: Mapping[str, object]) -> list[Mapping[str, object]]:
    backend_evidence = run_record.get("backend_evidence")
    if not isinstance(backend_evidence, Mapping):
        return []
    refs = backend_evidence.get("evidence_references")
    if not isinstance(refs, list):
        return []
    return [item for item in refs if isinstance(item, Mapping)]


def _flatten_behavior_events(runtime_snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    behavior_history = runtime_snapshot.get("participant_behavior_history")
    events: list[dict[str, object]] = []
    if not isinstance(behavior_history, Mapping):
        return events
    for event_list in behavior_history.values():
        if not isinstance(event_list, list):
            continue
        events.extend(dict(event) for event in event_list if isinstance(event, Mapping))
    return events


def _collect_episode_ids(
    runtime_snapshot: Mapping[str, object], behavior_events: Sequence[Mapping[str, object]]
) -> set[str]:
    episode_ids: set[str] = set()
    results = runtime_snapshot.get("participant_episode_results")
    if isinstance(results, Mapping):
        for payload in results.values():
            if isinstance(payload, Mapping) and isinstance(payload.get("episode_id"), str):
                episode_ids.add(payload["episode_id"])
    history = runtime_snapshot.get("participant_episode_history")
    if isinstance(history, Mapping):
        for event_list in history.values():
            if not isinstance(event_list, list):
                continue
            for event in event_list:
                if isinstance(event, Mapping) and isinstance(event.get("episode_id"), str):
                    episode_ids.add(event["episode_id"])
    for event in behavior_events:
        episode_id = event.get("episode_id")
        if isinstance(episode_id, str) and episode_id:
            episode_ids.add(episode_id)
    return episode_ids


def _collect_action_ids(behavior_events: Sequence[Mapping[str, object]]) -> set[str]:
    return {
        event["action_instance_id"]
        for event in behavior_events
        if isinstance(event.get("action_instance_id"), str) and event["action_instance_id"]
    }


def _map_action_to_episode(behavior_events: Sequence[Mapping[str, object]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for event in behavior_events:
        action_id = event.get("action_instance_id")
        episode_id = event.get("episode_id")
        if isinstance(action_id, str) and action_id and isinstance(episode_id, str) and episode_id:
            mapping.setdefault(action_id, episode_id)
    return mapping


def _map_action_to_events(
    behavior_events: Sequence[Mapping[str, object]],
) -> dict[str, list[Mapping[str, object]]]:
    mapping: dict[str, list[Mapping[str, object]]] = {}
    for event in behavior_events:
        action_id = event.get("action_instance_id")
        if isinstance(action_id, str) and action_id:
            mapping.setdefault(action_id, []).append(event)
    return mapping


# ---------------------------------------------------------------------------
# Mutable accumulator: nodes/edges/clock-contexts are all order-independent
# sets (Stage 1's CorrelationProjection canonicalizes by sorting), so the
# accumulator only needs to guard against a ref being redeclared under a
# conflicting ref_kind and against a clock source being read twice.
# ---------------------------------------------------------------------------


@dataclass
class _Accumulator:
    clock_provider: ClockProvider
    rules: CorrelationRuleSet
    nodes: dict[str, CorrelationNode] = field(default_factory=dict)
    edges: list[CorrelationEdge] = field(default_factory=list)
    clock_contexts: dict[tuple[str, str], ClockContext] = field(default_factory=dict)

    def add_node(self, ref: str, ref_kind: str) -> str:
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
        return self.clock_ref(
            self.clock_context_for(source_kind, source_id, observer_effect_ref=observer_effect_ref)
        )


# ---------------------------------------------------------------------------
# Section builders — each owns one concern and stays small (ruff C901 gate).
# ---------------------------------------------------------------------------


def _add_run_node(acc: _Accumulator, run_ref: str) -> None:
    acc.add_node(run_ref, "attempt-run")


def _add_planned_trial(acc: _Accumulator, run_record: Mapping[str, object], run_ref: str) -> None:
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
    for address, payload in orchestration.items():
        if not isinstance(payload, Mapping):
            continue
        address_ref = _add_orchestration_address(acc, address, payload, run_ref)
        history = payload.get("history")
        if isinstance(history, list):
            events = [event for event in history if isinstance(event, Mapping)]
            _add_orchestration_history(acc, address_ref, events)


def _participant_address_of(events: Sequence[Mapping[str, object]]) -> str | None:
    for event in events:
        addr = event.get("participant_address")
        if isinstance(addr, str) and addr:
            return addr
    return None


def _clocks_reconcilable(a: ClockContext, b: ClockContext) -> bool:
    """Whether two clock contexts' timestamps can be honestly compared.

    Only when they share a timestamp domain (the same clock) — comparing raw
    timestamps across DIFFERENT domains with no known measured offset would
    fabricate clock-qualified precision that does not exist. This is the
    OBS-002 gate that stops timestamp proximity in one domain from
    masquerading as a cross-domain temporal association.
    """
    return a.timestamp_domain == b.timestamp_domain


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
    are only comparable when they share a timestamp domain: then an overlap
    is a ``TIME_WINDOW_CANDIDATE`` (never EXPLICIT/DECLARED — no ACES contract
    propagates a shared id across the evaluation/participant namespaces). When
    the domains differ and no offset reconciles them, overlap cannot be
    established, so the edge is an explicit ``GAP_OR_UNKNOWN`` disclosing the
    unreconciled clocks rather than a candidate that merely *looks*
    clock-qualified. Every emitted edge names BOTH clock inputs — the
    evaluator via ``clock_context_ref``, the participant via
    ``disclosure_refs`` — so the comparison basis is auditable.
    """
    eval_clock_ref = acc.clock_ref(eval_ctx)
    for action_id in action_ids:
        events = action_to_events.get(action_id, ())
        participant_address = _participant_address_of(events)
        if participant_address is None:
            continue
        part_ctx = acc.clock_context_for("participant", participant_address)
        part_clock_ref = acc.clock_ref(part_ctx)
        if not _clocks_reconcilable(eval_ctx, part_ctx):
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
    """External evidence references (e.g. ``backend_evidence.evidence_references``)
    carry no participant/episode/action/run identifier at all — GAP_OR_UNKNOWN
    is the only honest association method (preflight: "an external evidence
    source with no id propagation on the Python side")."""
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
