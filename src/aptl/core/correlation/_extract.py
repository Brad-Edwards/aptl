"""Run-archive parsing/extraction helpers for the OBS-002 correlation builder.

Split out of :mod:`aptl.core.correlation._assemble` to keep each module within
the repo's per-file line budget (SonarCloud ``python:S104``). Pure, read-only
helpers over the already-parsed ``aptl.run-record/v1`` manifest and the ACES
orchestrator's ``orchestration/<addr>/*`` payloads — no I/O, no wall clock, no
identity minting. Best-effort throughout: EXP-002/REP-001 do not thread
``planned_trial_id`` or augmentation disclosures into the run record today, so
these read a handful of plausible paths and are silently absent (never
fabricated) when a field truly is not there.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime

from aptl.core.correlation.identity import stable_ref
from aptl.core.correlation.models import ClockContext


def _content_signature(payload: object) -> str:
    """Canonical string signature for grouping byte-identical raw dicts.

    Sorted keys make the signature independent of a dict's own key order;
    list *values* are left as-is because their order is meaningful source
    content (e.g. ``shared_state_refs``), not incidental ingestion order.
    """
    return json.dumps(payload, sort_keys=True, default=str)


def _derive_distinct_refs(items: Sequence[object], *, domain: bytes) -> list[str]:
    """Return one content-derived ref per item, positionally aligned with ``items``.

    Each ref is derived from the item's own content plus how many *identical*
    items were already counted (an occurrence index within the content-keyed
    multiset) — never from list position. Re-ordering ``items`` (reordered
    ingestion) yields the identical *set* of refs, while two genuinely
    byte-identical items still resolve to two distinct refs rather than
    collapsing into one (preflight: "Do not collapse duplicate events").
    """
    occurrence_counts: dict[str, int] = {}
    refs: list[str] = []
    for item in items:
        signature = _content_signature(item)
        occurrence = occurrence_counts.get(signature, 0)
        occurrence_counts[signature] = occurrence + 1
        refs.append(stable_ref(signature, str(occurrence), domain=domain))
    return refs


def _parse_rfc3339(value: object) -> datetime | None:
    """Parse an RFC-3339 timestamp string, or ``None`` when absent/unparseable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _events_window(events: Sequence[Mapping[str, object]]) -> tuple[datetime, datetime] | None:
    """Return ``(earliest, latest)`` parsed timestamps among ``events``, or
    ``None`` when none carry a parseable timestamp (a missing source timestamp
    is a gap, never fabricated)."""
    timestamps = [ts for ts in (_parse_rfc3339(e.get("timestamp")) for e in events) if ts is not None]
    if not timestamps:
        return None
    return min(timestamps), max(timestamps)


def _evaluator_window(payload: Mapping[str, object]) -> tuple[datetime, datetime] | None:
    """Return an evaluator result's ``(earliest, latest)`` window from its
    ``started_at``/``updated_at`` fields, or ``None`` when neither is a
    parseable timestamp."""
    started = _parse_rfc3339(payload.get("started_at"))
    updated = _parse_rfc3339(payload.get("updated_at"))
    if started is None:
        started = updated
    if updated is None:
        updated = started
    if started is None or updated is None:
        return None
    return (started, updated) if started <= updated else (updated, started)


def _windows_overlap(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> bool:
    """Whether two closed time windows overlap (endpoints inclusive)."""
    return a[0] <= b[1] and b[0] <= a[1]


def _clocks_reconcilable(a: ClockContext, b: ClockContext) -> bool:
    """Whether two clock contexts' timestamps can be honestly compared.

    Only when they share a timestamp domain (the same clock) — comparing raw
    timestamps across DIFFERENT domains with no known measured offset would
    fabricate clock-qualified precision that does not exist. This is the
    OBS-002 gate that stops timestamp proximity in one domain from
    masquerading as a cross-domain temporal association.
    """
    return a.timestamp_domain == b.timestamp_domain


def _runtime_snapshot(run_record: Mapping[str, object]) -> Mapping[str, object]:
    """Return the embedded ``aces.runtime_snapshot`` mapping, or ``{}``."""
    aces_section = run_record.get("aces")
    if not isinstance(aces_section, Mapping):
        return {}
    snapshot = aces_section.get("runtime_snapshot")
    return snapshot if isinstance(snapshot, Mapping) else {}


def _find_planned_trial_id(run_record: Mapping[str, object]) -> str | None:
    """Best-effort planned-trial id from the run record, or ``None`` when the
    field is not threaded through (the common case today) — never fabricated."""
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
    """Observer-effect / augmentation disclosure refs from the run record's
    realization section (best-effort; empty when absent — never fabricated)."""
    realization: object = {}
    aces_section = run_record.get("aces")
    if isinstance(aces_section, Mapping):
        realization = aces_section.get("realization")
    result: tuple[str, ...] = ()
    if isinstance(realization, Mapping):
        for key in ("disclosure_refs", "augmentation_disclosure_refs"):
            raw = realization.get(key)
            if isinstance(raw, list) and raw:
                result = tuple(str(item) for item in raw if isinstance(item, str) and item)
                break
    return result


def _external_evidence_references(run_record: Mapping[str, object]) -> list[Mapping[str, object]]:
    """External evidence reference dicts from ``backend_evidence`` (or ``[]``)."""
    backend_evidence = run_record.get("backend_evidence")
    if not isinstance(backend_evidence, Mapping):
        return []
    refs = backend_evidence.get("evidence_references")
    if not isinstance(refs, list):
        return []
    return [item for item in refs if isinstance(item, Mapping)]


def _flatten_behavior_events(runtime_snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    """Flatten ``participant_behavior_history`` (address → event list) into a
    single ordered list of event dicts."""
    behavior_history = runtime_snapshot.get("participant_behavior_history")
    events: list[dict[str, object]] = []
    if not isinstance(behavior_history, Mapping):
        return events
    for event_list in behavior_history.values():
        if not isinstance(event_list, list):
            continue
        events.extend(dict(event) for event in event_list if isinstance(event, Mapping))
    return events


def _episode_ids_from_results(runtime_snapshot: Mapping[str, object]) -> set[str]:
    """Episode ids declared in ``participant_episode_results``."""
    out: set[str] = set()
    results = runtime_snapshot.get("participant_episode_results")
    if isinstance(results, Mapping):
        for payload in results.values():
            if isinstance(payload, Mapping) and isinstance(payload.get("episode_id"), str):
                out.add(payload["episode_id"])
    return out


def _episode_ids_from_history(runtime_snapshot: Mapping[str, object]) -> set[str]:
    """Episode ids appearing across ``participant_episode_history`` event lists."""
    out: set[str] = set()
    history = runtime_snapshot.get("participant_episode_history")
    if not isinstance(history, Mapping):
        return out
    for event_list in history.values():
        if not isinstance(event_list, list):
            continue
        for event in event_list:
            if isinstance(event, Mapping) and isinstance(event.get("episode_id"), str):
                out.add(event["episode_id"])
    return out


def _episode_ids_from_events(behavior_events: Sequence[Mapping[str, object]]) -> set[str]:
    """Episode ids stamped on behavior-history events."""
    return {
        event["episode_id"]
        for event in behavior_events
        if isinstance(event.get("episode_id"), str) and event["episode_id"]
    }


def _collect_episode_ids(
    runtime_snapshot: Mapping[str, object], behavior_events: Sequence[Mapping[str, object]]
) -> set[str]:
    """Union of every participant episode id present anywhere in the snapshot
    (results, history, and behavior events)."""
    return (
        _episode_ids_from_results(runtime_snapshot)
        | _episode_ids_from_history(runtime_snapshot)
        | _episode_ids_from_events(behavior_events)
    )


def _collect_action_ids(behavior_events: Sequence[Mapping[str, object]]) -> set[str]:
    """Distinct ``action_instance_id`` values across behavior events."""
    return {
        event["action_instance_id"]
        for event in behavior_events
        if isinstance(event.get("action_instance_id"), str) and event["action_instance_id"]
    }


def _map_action_to_episode(behavior_events: Sequence[Mapping[str, object]]) -> dict[str, str]:
    """Map each action instance id to the episode id it was first seen under."""
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
    """Group behavior events by their ``action_instance_id``."""
    mapping: dict[str, list[Mapping[str, object]]] = {}
    for event in behavior_events:
        action_id = event.get("action_instance_id")
        if isinstance(action_id, str) and action_id:
            mapping.setdefault(action_id, []).append(event)
    return mapping


def _participant_address_of(events: Sequence[Mapping[str, object]]) -> str | None:
    """First non-empty ``participant_address`` among ``events``, or ``None``."""
    for event in events:
        addr = event.get("participant_address")
        if isinstance(addr, str) and addr:
            return addr
    return None
