"""Acquire adapter-supplied native evidence into the run ledger."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.correlation.clock import ClockProvider, SystemClockProvider
from aptl.core.evidence.adapters.sources import (
    SourceResult,
    WindowedSource,
    _to_outcome,
)
from aptl.core.evidence.content_store import create_run_json_once
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition, CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome, RunScope
from aptl.core.experiment.capture_registry import CaptureBinding
from aptl.core.runstore import LocalRunStore
from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    create_exclusive_nofollow,
    listdir_contained_nofollow,
    open_contained_nofollow,
    read_contained_nofollow,
)
from aptl.backends.identity import BackendIdentity
from aptl.backends.scenario_capture import (
    ResolvedScenarioCapture,
    ScenarioCaptureContext,
)
from aptl.backends.scenario_capture_discovery import resolve_scenario_capture

if TYPE_CHECKING:
    from aptl.core.experiment.capture_plan import CapturePlan


_ACTIVE_AUTHORITY_DIR = ".aptl/capture-authorities"
_FINALIZED_AUTHORITY_DIR = ".aptl/capture-finalized"
_FAILED_ACTIVATION_DIR = ".aptl/capture-activation-failed"
_FAILED_FINALIZATION_DIR = ".aptl/capture-finalization-failed"

@dataclass(frozen=True)
class _OnDemandHandle:
    """Collector context and the exact native-check start instant."""

    context: CollectorContext
    started_at: str


def _parse_timestamp(value: str) -> datetime:
    """Parse the canonical UTC timestamp form emitted by capture clocks."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _deadline(started_at: str, seconds: float) -> str:
    """Return the admitted deadline measured from a collector start."""

    value = _parse_timestamp(started_at) + timedelta(seconds=seconds)
    return value.isoformat().replace("+00:00", "Z")


def _source_times_inside_actual_window(
    result: SourceResult, started_at: str, finished_at: str
) -> bool:
    """Return whether all reported source instants fit the actual window."""

    try:
        start = _parse_timestamp(started_at)
        finish = _parse_timestamp(finished_at)
        source_min = (
            _parse_timestamp(result.source_min_time)
            if result.source_min_time is not None
            else None
        )
        source_max = (
            _parse_timestamp(result.source_max_time)
            if result.source_max_time is not None
            else None
        )
    except (TypeError, ValueError):
        return False
    return (
        start <= finish
        and (source_min is None or start <= source_min <= finish)
        and (source_max is None or start <= source_max <= finish)
        and (source_min is None or source_max is None or source_min <= source_max)
    )


class _OnDemandNativeCollector:
    """Run one bounded native check and close its window after the check.

    Native adapter checks create fresh evidence while ``fetch`` runs.
    The query receives the admitted future deadline, but the outcome records
    the actual post-query finish. Source timestamps outside that actual window
    are rejected as clock skew.
    """

    def __init__(self, registration_id: str, source: WindowedSource) -> None:
        self._registration_id = registration_id
        self._source = source

    @property
    def registration_id(self) -> str:
        return self._registration_id

    @staticmethod
    def start(context: CollectorContext) -> _OnDemandHandle:
        return _OnDemandHandle(context=context, started_at=context.clock.now())

    def stop(self, handle: _OnDemandHandle) -> CollectorOutcome:
        result = self._source.fetch(
            handle.started_at,
            _deadline(handle.started_at, handle.context.deadline_seconds),
        )
        finished_at = handle.context.clock.now()
        if not _source_times_inside_actual_window(
            result, handle.started_at, finished_at
        ):
            result = SourceResult(status=CollectorStatus.CLOCK_SKEW)
        return _to_outcome(result, handle.started_at, finished_at)


def _native_bindings(
    plan: CapturePlan,
    selection: ResolvedScenarioCapture,
) -> tuple[CaptureBinding, ...]:
    """Select immediate bindings declared by the admitted adapter."""

    return tuple(
        binding
        for binding in plan.runtime_bindings()
        if binding.registration_id
        in selection.contribution.native_registration_ids
    )


def _persist_capture_plan(
    plan: CapturePlan, run_store: LocalRunStore, run_id: str
) -> None:
    """Create the run and seal the admitted capture plan exactly once."""

    run_store.create_run(run_id)
    create_run_json_once(
        run_store,
        run_id,
        f"evidence/capture-plans/{plan.plan_id}.json",
        json.loads(plan.canonical_bytes),
    )


def persist_active_transcript_authority(
    *,
    project_dir: Path,
    plan: CapturePlan,
    binding: CaptureBinding,
    run_store: LocalRunStore,
    run_id: str,
    capture_selection: ResolvedScenarioCapture,
) -> None:
    """Persist the minimum restart-safe authority needed to finalize at stop."""

    if not isinstance(run_store, LocalRunStore):
        raise TypeError("transcript capture requires a local run store")
    transcript_id = capture_selection.contribution.transcript_registration_id
    if transcript_id is None or binding.registration_id != transcript_id:
        raise ValueError("unsupported transcript binding")
    _persist_capture_plan(plan, run_store, run_id)
    payload = {
        "schema_version": "aptl-active-transcript-authority/v1",
        "run_id": run_id,
        "run_store_base": str(run_store.base_dir),
        "capture_plan_id": plan.plan_id,
        "binding": binding.binding_projection(),
        "capture_adapter": {
            "pack_id": capture_selection.context.pack.pack_id,
            "pack_version": capture_selection.context.pack.pack_version,
            "pack_set_digest": capture_selection.context.pack.set_digest,
            "backend_target_name": capture_selection.context.backend.target_name,
            "backend_target_version": capture_selection.context.backend.target_version,
            "backend_profile": capture_selection.context.backend.profile,
            "backend_transport": capture_selection.context.backend.transport,
            "provider_id": capture_selection.provider_id,
            "distribution": capture_selection.distribution,
            "distribution_version": capture_selection.distribution_version,
            "entry_point": capture_selection.entry_point,
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    relative = f"{_ACTIVE_AUTHORITY_DIR}/{run_id}.json"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("active transcript authority conflict") from None


def _contained_entry_exists(project_dir: Path, relative: str) -> bool:
    """Return whether a contained marker exists, propagating unsafe failures."""

    try:
        read_contained_nofollow(project_dir, relative)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return False
        raise
    return True


def _failed_transcript_marker_exists(
    project_dir: Path,
    directory: str,
    name: str,
    authority: Mapping[str, object],
    mismatch_error: str,
) -> bool:
    """Validate and report one terminal failure marker for an authority."""

    relative = f"{directory}/{name}"
    if not _contained_entry_exists(project_dir, relative):
        return False
    failed = json.loads(read_contained_nofollow(project_dir, relative))
    if not isinstance(failed, dict) or any(
        failed.get(key) != authority.get(key) for key in ("run_id", "capture_plan_id")
    ):
        raise ValueError(mismatch_error)
    return True


def load_active_transcript_authorities(
    project_dir: Path,
) -> tuple[dict[str, object], ...]:
    """Read every contained active authority; a malformed entry fails closed."""

    try:
        names = listdir_contained_nofollow(project_dir, _ACTIVE_AUTHORITY_DIR)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return ()
        raise
    authorities: list[dict[str, object]] = []
    for name in names:
        if not name.endswith(".json"):
            raise ValueError("unexpected active transcript authority entry")
        value = json.loads(
            read_contained_nofollow(project_dir, f"{_ACTIVE_AUTHORITY_DIR}/{name}")
        )
        if not isinstance(value, dict):
            raise ValueError("active transcript authority is not an object")
        if _contained_entry_exists(project_dir, f"{_FINALIZED_AUTHORITY_DIR}/{name}"):
            continue
        terminal_failures = (
            (
                _FAILED_ACTIVATION_DIR,
                "failed transcript activation marker mismatch",
            ),
            (
                _FAILED_FINALIZATION_DIR,
                "failed transcript finalization marker mismatch",
            ),
        )
        if any(
            _failed_transcript_marker_exists(
                project_dir, directory, name, value, mismatch_error
            )
            for directory, mismatch_error in terminal_failures
        ):
            continue
        authorities.append(value)
    return tuple(authorities)


def mark_transcript_activation_failed(
    *, project_dir: Path, plan_id: str, run_id: str
) -> None:
    """Retain an auditable terminal marker for an unactivated startup run."""

    name = f"{run_id}.json"
    state = json.loads(
        read_contained_nofollow(project_dir, f"{_ACTIVE_AUTHORITY_DIR}/{name}")
    )
    if (
        not isinstance(state, dict)
        or state.get("run_id") != run_id
        or state.get("capture_plan_id") != plan_id
    ):
        raise ValueError("failed transcript activation identity mismatch")
    payload = {
        "schema_version": "aptl-transcript-activation-failed/v1",
        "run_id": run_id,
        "capture_plan_id": plan_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    relative = f"{_FAILED_ACTIVATION_DIR}/{name}"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("failed transcript activation marker conflict") from None


def mark_transcript_finalization_failed(
    *, project_dir: Path, state: Mapping[str, object]
) -> None:
    """Retain an auditable terminal marker when teardown cannot seal capture."""

    run_id = str(state["run_id"])
    plan_id = str(state["capture_plan_id"])
    name = f"{run_id}.json"
    active = json.loads(
        read_contained_nofollow(project_dir, f"{_ACTIVE_AUTHORITY_DIR}/{name}")
    )
    if (
        not isinstance(active, dict)
        or active.get("run_id") != run_id
        or active.get("capture_plan_id") != plan_id
    ):
        raise ValueError("failed transcript finalization identity mismatch")
    payload = {
        "schema_version": "aptl-transcript-finalization-failed/v1",
        "run_id": run_id,
        "capture_plan_id": plan_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    relative = f"{_FAILED_FINALIZATION_DIR}/{name}"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("failed transcript finalization marker conflict") from None


def _mark_transcript_finalized(
    project_dir: Path, state: Mapping[str, object], result: AcquisitionResult
) -> None:
    """Seal a restart-safe marker after a transcript reaches ready state."""

    run_id = str(state["run_id"])
    payload = {
        "schema_version": "aptl-finalized-transcript-authority/v1",
        "run_id": run_id,
        "capture_plan_id": state["capture_plan_id"],
        "disposition": result.disposition.value,
        "evidence_record_ids": [record.evidence_record_id for record in result.records],
    }
    create_exclusive_nofollow(
        project_dir,
        f"{_FINALIZED_AUTHORITY_DIR}/{run_id}.json",
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )


def _expected_transcript_session_ids(
    store_base: Path,
    run_id: str,
    *,
    max_sessions: int,
) -> tuple[str, ...]:
    """Read the MCP-owned expected-session census without following links."""

    relative_dir = f"{run_id}/mcp-side/sessions"
    try:
        names = listdir_contained_nofollow(store_base, relative_dir)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return ()
        raise
    if len(names) > max_sessions:
        raise ValueError("transcript session census exceeds admitted limits")
    session_ids: list[str] = []
    for name in names:
        if not name.endswith(".jsonl"):
            raise ValueError("unexpected transcript session census entry")
        session_id = name.removesuffix(".jsonl")
        if (
            not session_id
            or session_id.startswith(".")
            or ".." in session_id
            or re.fullmatch(r"\w[\w.-]*", session_id, flags=re.ASCII) is None
        ):
            raise ValueError("invalid transcript session census identity")
        with open_contained_nofollow(store_base, f"{relative_dir}/{name}") as handle:
            # Opening is the check: the census requires a contained regular
            # file, while its content remains owned by the MCP capture path.
            handle.read(0)
        session_ids.append(session_id)
    if len(session_ids) != len(set(session_ids)):
        raise ValueError("duplicate transcript session census identity")
    return tuple(session_ids)


def _export_transcript_payload(
    backend: object,
    store_base: Path,
    run_id: str,
    binding: CaptureBinding,
) -> object | None:
    """Quiesce the broker and export against the stable session census."""

    quiesce = getattr(backend, "quiesce_capture_apparatus", None)
    export = getattr(backend, "export_capture_apparatus", None)
    try:
        if not callable(quiesce) or not callable(export) or not quiesce():
            return None
        # Admission is now closed under the broker's registration lock.
        # Read the independent MCP census only after that boundary is stable.
        expected_session_ids = _expected_transcript_session_ids(
            store_base,
            run_id,
            max_sessions=binding.limits.max_artifact_count // 2,
        )
        return export(expected_session_ids=expected_session_ids)
    except (OSError, PathContainmentError, TypeError, ValueError):
        return None


def _validated_activation_time(
    payload: object,
    *,
    run_id: str,
    plan_id: str,
    clock: ClockProvider,
    transcript_registration_id: str,
) -> tuple[object | None, str]:
    """Validate broker authority and return a safe payload/start boundary."""

    authority = payload.get("authority") if isinstance(payload, Mapping) else None
    expected_authority = {
        "run_id": run_id,
        "plan_id": plan_id,
        "binding_id": transcript_registration_id,
    }
    valid = isinstance(authority, Mapping) and all(
        authority.get(key) == value for key, value in expected_authority.items()
    )
    if not valid:
        return None, clock.now()
    return payload, str(authority.get("activated_at", ""))


def finalize_active_transcript_authority(
    *,
    project_dir: Path,
    state: Mapping[str, object],
    backend: object,
    expected_run_store_base: Path,
    clock: ClockProvider | None = None,
) -> AcquisitionResult:
    """Quiesce, validate, and persist one restart-safe full-run transcript."""

    store_base = Path(str(state["run_store_base"])).resolve()
    if store_base != expected_run_store_base.resolve():
        raise ValueError("transcript run store does not match configured run storage")
    capture_selection = _capture_selection_from_state(state)
    runtime_adapter = capture_selection.contribution.runtime_adapter
    binding_loader = getattr(runtime_adapter, "binding_from_projection", None)
    collector_factory = getattr(
        runtime_adapter, "finalized_transcript_collector", None
    )
    if not callable(binding_loader) or not callable(collector_factory):
        raise ValueError("capture adapter cannot finalize transcripts")
    binding = binding_loader(state["binding"])
    if not isinstance(binding, CaptureBinding):
        raise ValueError("capture adapter returned an invalid binding")
    transcript_id = capture_selection.contribution.transcript_registration_id
    if transcript_id is None or binding.registration_id != transcript_id:
        raise ValueError("capture adapter transcript identity mismatch")
    plan_id = str(state["capture_plan_id"])
    run_id = str(state["run_id"])
    if binding.capture_spec_id != plan_id:
        raise ValueError("transcript binding plan identity mismatch")
    active_clock = clock or SystemClockProvider()
    payload, activated_at = _validated_activation_time(
        _export_transcript_payload(backend, store_base, run_id, binding),
        run_id=run_id,
        plan_id=plan_id,
        clock=active_clock,
        transcript_registration_id=transcript_id,
    )
    collector = collector_factory(binding, payload, activated_at)
    result = acquire_evidence(
        bindings=(binding,),
        collectors={binding.registration_id: collector},
        run_store=LocalRunStore(store_base),
        scope=RunScope(
            run_id=run_id,
            planned_trial_id=plan_id,
            attempt_id="teardown",
        ),
        clock=active_clock,
    )
    if result.disposition is AcquisitionDisposition.SEALED_READY:
        _mark_transcript_finalized(project_dir, state, result)
    return result


def _capture_selection_from_state(
    state: Mapping[str, object],
) -> ResolvedScenarioCapture:
    """Re-resolve the exact persisted adapter and reject provenance drift."""

    from aptl.core.scenario_bundle import PackIdentity

    adapter = state.get("capture_adapter")
    if not isinstance(adapter, Mapping):
        raise ValueError("active authority has no capture adapter identity")
    try:
        context = ScenarioCaptureContext(
            pack=PackIdentity(
                str(adapter["pack_id"]),
                str(adapter["pack_version"]),
                str(adapter["pack_set_digest"]),
            ),
            backend=BackendIdentity(
                str(adapter["backend_target_name"]),
                str(adapter["backend_target_version"]),
                str(adapter["backend_profile"]),
                transport=str(adapter["backend_transport"]),
            ),
        )
    except KeyError:
        raise ValueError("active authority capture adapter is incomplete") from None
    resolved = resolve_scenario_capture(context)
    observed = (
        resolved.provider_id,
        resolved.distribution,
        resolved.distribution_version,
        resolved.entry_point,
    )
    expected = tuple(
        str(adapter[name])
        for name in (
            "provider_id",
            "distribution",
            "distribution_version",
            "entry_point",
        )
    )
    if observed != expected:
        raise ValueError("capture adapter provenance changed")
    return resolved


from aptl.backends._raes_native_evidence_acquisition import (
    NativeEvidenceRequest,
    acquire_native_evidence,
)


__all__ = (
    "NativeEvidenceRequest",
    "acquire_native_evidence",
    "finalize_active_transcript_authority",
    "load_active_transcript_authorities",
    "mark_transcript_activation_failed",
    "mark_transcript_finalization_failed",
    "persist_active_transcript_authority",
)
