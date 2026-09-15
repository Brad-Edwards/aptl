"""Acquire the admitted TechVault native evidence into the run ledger."""

from __future__ import annotations

import base64
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
from aptl.core.evidence.adapters.techvault import (
    RedteamSessionTranscriptSource,
    TranscriptFrame,
    TranscriptSession,
)
from aptl.core.evidence.adapters.techvault_native import TechVaultNativeEvidenceOwner
from aptl.core.evidence.content_store import create_run_json_once
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition, CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome, RunScope
from aptl.core.experiment.capture_registry import (
    DEFAULT_COLLECTOR_REGISTRY,
    CaptureBinding,
    CaptureLimits,
    CaptureVisibility,
)
from aptl.core.runstore import LocalRunStore
from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    create_exclusive_nofollow,
    listdir_contained_nofollow,
    open_contained_nofollow,
    read_contained_nofollow,
)

if TYPE_CHECKING:
    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.core.experiment.capture_plan import CapturePlan


NATIVE_TECHVAULT_REGISTRATIONS = frozenset(
    {
        "aptl.collector.cortex-enrichment",
        "aptl.collector.suricata-rule-readiness",
        "aptl.collector.suricata-wazuh-sqli",
    }
)
TRANSCRIPT_REGISTRATION = "aptl.collector.redteam-session-transcript"
_ACTIVE_AUTHORITY_DIR = ".aptl/capture-authorities"
_FINALIZED_AUTHORITY_DIR = ".aptl/capture-finalized"


@dataclass(frozen=True)
class _OnDemandHandle:
    context: CollectorContext
    started_at: str


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _deadline(started_at: str, seconds: float) -> str:
    value = _parse_timestamp(started_at) + timedelta(seconds=seconds)
    return value.isoformat().replace("+00:00", "Z")


def _source_times_inside_actual_window(
    result: SourceResult, started_at: str, finished_at: str
) -> bool:
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

    The native TechVault checks create fresh evidence while ``fetch`` runs.
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


def _native_bindings(plan: CapturePlan) -> tuple[CaptureBinding, ...]:
    return tuple(
        binding
        for binding in plan.runtime_bindings()
        if binding.registration_id in NATIVE_TECHVAULT_REGISTRATIONS
    )


def _persist_capture_plan(
    plan: CapturePlan, run_store: LocalRunStore, run_id: str
) -> None:
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
) -> None:
    """Persist the minimum restart-safe authority needed to finalize at stop."""

    if not isinstance(run_store, LocalRunStore):
        raise TypeError("transcript capture requires a local run store")
    if binding.registration_id != TRANSCRIPT_REGISTRATION:
        raise ValueError("unsupported transcript binding")
    _persist_capture_plan(plan, run_store, run_id)
    payload = {
        "schema_version": "aptl-active-transcript-authority/v1",
        "run_id": run_id,
        "run_store_base": str(run_store.base_dir),
        "capture_plan_id": plan.plan_id,
        "binding": binding.binding_projection(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    relative = f"{_ACTIVE_AUTHORITY_DIR}/{run_id}.json"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("active transcript authority conflict") from None


def load_active_transcript_authorities(project_dir: Path) -> tuple[dict, ...]:
    """Read every contained active authority; a malformed entry fails closed."""

    try:
        names = listdir_contained_nofollow(project_dir, _ACTIVE_AUTHORITY_DIR)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return ()
        raise
    authorities: list[dict] = []
    for name in names:
        if not name.endswith(".json"):
            raise ValueError("unexpected active transcript authority entry")
        value = json.loads(
            read_contained_nofollow(project_dir, f"{_ACTIVE_AUTHORITY_DIR}/{name}")
        )
        if not isinstance(value, dict):
            raise ValueError("active transcript authority is not an object")
        try:
            read_contained_nofollow(project_dir, f"{_FINALIZED_AUTHORITY_DIR}/{name}")
        except PathContainmentError as exc:
            if exc.reason != REASON_NOT_FOUND:
                raise
        else:
            continue
        authorities.append(value)
    return tuple(authorities)


def _binding_from_projection(value: object) -> CaptureBinding:
    if not isinstance(value, Mapping):
        raise ValueError("transcript binding is not an object")
    data = dict(value)
    expected_keys = set(_binding_schema_keys())
    if set(data) != expected_keys:
        raise ValueError("transcript binding fields do not match the schema")
    for key in ("max_bytes", "max_artifact_count", "max_duration_s"):
        item = data[key]
        if not isinstance(item, int) or isinstance(item, bool) or item < 1:
            raise ValueError("transcript binding limit is invalid")
    limits = CaptureLimits(
        max_bytes=data.pop("max_bytes"),
        max_artifact_count=data.pop("max_artifact_count"),
        max_duration_s=data.pop("max_duration_s"),
    )
    for key in ("redaction_required", "loss_disclosure_required"):
        if not isinstance(data[key], bool):
            raise ValueError("transcript binding boolean is invalid")
    data["visibility_class"] = CaptureVisibility(data["visibility_class"])
    for key in (
        "window_refs",
        "expected_media_types",
        "required_artifact_roles",
        "integrity_requirements",
    ):
        sequence = data[key]
        if (
            not isinstance(sequence, list)
            or any(not isinstance(item, str) or not item for item in sequence)
            or len(sequence) != len(set(sequence))
        ):
            raise ValueError("transcript binding sequence is invalid")
        data[key] = tuple(sequence)
    binding = CaptureBinding(**data, limits=limits)
    if binding.registration_id != TRANSCRIPT_REGISTRATION:
        raise ValueError("active authority is not a transcript binding")
    registrations = {
        item.registration_id: item for item in DEFAULT_COLLECTOR_REGISTRY.registrations
    }
    registration = registrations.get(binding.registration_id)
    if (
        registration is None
        or registration.effective_config_digest() != binding.effective_config_digest
        or registration.implementation_version != binding.implementation_version
        or registration.contract_version != binding.contract_version
        or registration.limits != binding.limits
        or registration.visibility_class is not binding.visibility_class
    ):
        raise ValueError("transcript registration no longer matches its pin")
    return binding


def _binding_schema_keys() -> tuple[str, ...]:
    """Return the exact create-once binding projection field set."""

    registration = next(
        item
        for item in DEFAULT_COLLECTOR_REGISTRY.registrations
        if item.registration_id == TRANSCRIPT_REGISTRATION
    )
    sample = CaptureBinding(
        capture_spec_id="sample",
        requirement_id="sample",
        window_refs=("sample",),
        registration_id=registration.registration_id,
        implementation_version=registration.implementation_version,
        contract_version=registration.contract_version,
        effective_config_digest=registration.effective_config_digest(),
        channel_ref_id="sample",
        channel_ref_version=None,
        channel_kind=registration.channel_kind,
        capture_kind=registration.capture_kind,
        capture_scope=registration.capture_scope,
        expected_media_types=("text/plain",),
        required_artifact_roles=("participant_session_transcript",),
        sensitivity="plain",
        redaction_required=True,
        redaction_policy="redact_secrets",
        integrity_requirements=("chain_of_custody",),
        retention_policy="run_lifetime",
        loss_disclosure_required=True,
        visibility_class=registration.visibility_class,
        limits=registration.limits,
    )
    return tuple(sample.binding_projection())


def _transcript_sessions(
    payload: object,
    limits: CaptureLimits,
) -> tuple[tuple[str, ...], tuple[TranscriptSession, ...]]:
    if not isinstance(payload, Mapping):
        raise ValueError("capture export is not an object")
    expected_raw = payload.get("expected_session_ids")
    sessions_raw = payload.get("sessions")
    if not isinstance(expected_raw, list) or not isinstance(sessions_raw, list):
        raise ValueError("capture export is incomplete")
    if len(expected_raw) > limits.max_artifact_count // 2 or any(
        not isinstance(value, str) or not value for value in expected_raw
    ):
        raise ValueError("capture session inventory is invalid")
    expected = tuple(expected_raw)
    if len(expected) != len(set(expected)):
        raise ValueError("capture session inventory has duplicates")
    sessions: list[TranscriptSession] = []
    retained_bytes = 0
    artifact_count = 2 * len(expected)
    for raw in sessions_raw:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("frames"), list):
            raise ValueError("capture session is incomplete")
        frames: list[TranscriptFrame] = []
        for item in raw["frames"]:
            if not isinstance(item, Mapping):
                raise ValueError("capture frame is not an object")
            sequence = item.get("sequence")
            encoded = item.get("data_b64")
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or not isinstance(encoded, str)
                or len(encoded) > 4 * 1024 * 1024 // 3 + 4
            ):
                raise ValueError("capture frame is invalid")
            decoded = base64.b64decode(encoded, validate=True)
            retained_bytes += len(decoded) + 256
            artifact_count += 1
            if (
                retained_bytes > limits.max_bytes
                or artifact_count > limits.max_artifact_count
            ):
                raise ValueError("capture export exceeds admitted limits")
            frames.append(
                TranscriptFrame(
                    sequence=sequence,
                    timestamp=str(item["timestamp"]),
                    direction=str(item["direction"]),
                    data=decoded,
                )
            )
        loss_count = raw.get("loss_count", 0)
        if not isinstance(loss_count, int) or isinstance(loss_count, bool):
            raise ValueError("capture loss count is invalid")
        sessions.append(
            TranscriptSession(
                session_id=str(raw["session_id"]),
                started_at=str(raw["started_at"]),
                finished_at=str(raw["finished_at"]),
                close_reason=str(raw["close_reason"]),
                frames=tuple(frames),
                final_chain_digest=str(raw["final_chain_digest"]),
                loss_count=loss_count,
            )
        )
    return expected, tuple(sessions)


class _FinalizedTranscriptCollector:
    def __init__(
        self,
        binding: CaptureBinding,
        payload: object,
        activated_at: str,
    ) -> None:
        self._binding = binding
        self._payload = payload
        self._activated_at = activated_at

    @property
    def registration_id(self) -> str:
        return self._binding.registration_id

    def start(self, context: CollectorContext) -> _OnDemandHandle:
        return _OnDemandHandle(context=context, started_at=self._activated_at)

    def stop(self, handle: _OnDemandHandle) -> CollectorOutcome:
        finished_at = handle.context.clock.now()
        try:
            expected, sessions = _transcript_sessions(
                self._payload,
                self._binding.limits,
            )
        except (KeyError, TypeError, ValueError):
            result = SourceResult(status=CollectorStatus.FINALIZATION_FAILURE)
        else:
            result = RedteamSessionTranscriptSource(
                lambda: expected,
                lambda: sessions,
            ).fetch(handle.started_at, finished_at)
        return _to_outcome(result, handle.started_at, finished_at)


def _mark_transcript_finalized(
    project_dir: Path, state: Mapping[str, object], result: AcquisitionResult
) -> None:
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
            or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", session_id) is None
        ):
            raise ValueError("invalid transcript session census identity")
        with open_contained_nofollow(store_base, f"{relative_dir}/{name}"):
            pass
        session_ids.append(session_id)
    if len(session_ids) != len(set(session_ids)):
        raise ValueError("duplicate transcript session census identity")
    return tuple(session_ids)


def finalize_active_transcript_authority(
    *,
    project_dir: Path,
    state: Mapping[str, object],
    backend: object,
    clock: ClockProvider | None = None,
) -> AcquisitionResult:
    """Quiesce, validate, and persist one restart-safe full-run transcript."""

    root = project_dir.resolve()
    store_base = Path(str(state["run_store_base"])).resolve()
    if not store_base.is_relative_to(root / ".aptl"):
        raise ValueError("transcript run store escapes project state")
    binding = _binding_from_projection(state["binding"])
    plan_id = str(state["capture_plan_id"])
    run_id = str(state["run_id"])
    if binding.capture_spec_id != plan_id:
        raise ValueError("transcript binding plan identity mismatch")
    quiesce = getattr(backend, "quiesce_capture_apparatus", None)
    export = getattr(backend, "export_capture_apparatus", None)
    payload = None
    try:
        if callable(quiesce) and callable(export) and quiesce():
            # Admission is now closed under the broker's registration lock.
            # Only after that boundary is stable do we read the independent,
            # MCP-owned expected-session census and reconcile it with export.
            expected_session_ids = _expected_transcript_session_ids(
                store_base,
                run_id,
                max_sessions=binding.limits.max_artifact_count // 2,
            )
            payload = export(expected_session_ids=expected_session_ids)
    except (OSError, PathContainmentError, TypeError, ValueError):
        payload = None
    authority = payload.get("authority") if isinstance(payload, Mapping) else None
    expected_authority = {
        "run_id": run_id,
        "plan_id": plan_id,
        "binding_id": TRANSCRIPT_REGISTRATION,
    }
    if not isinstance(authority, Mapping) or any(
        authority.get(key) != value for key, value in expected_authority.items()
    ):
        activated_at = (clock or SystemClockProvider()).now()
        payload = None
    else:
        activated_at = str(authority.get("activated_at", ""))
    collector = _FinalizedTranscriptCollector(binding, payload, activated_at)
    result = acquire_evidence(
        bindings=(binding,),
        collectors={binding.registration_id: collector},
        run_store=LocalRunStore(store_base),
        scope=RunScope(
            run_id=run_id,
            planned_trial_id=plan_id,
            attempt_id="teardown",
        ),
        clock=clock or SystemClockProvider(),
    )
    if result.disposition is AcquisitionDisposition.SEALED_READY:
        _mark_transcript_finalized(project_dir, state, result)
    return result


def acquire_native_evidence(
    *,
    plan: CapturePlan,
    backend: object,
    realization: AptlRealization,
    project_dir: Path,
    indexer_auth: tuple[str, str],
    thehive_api_key: str,
    run_store: LocalRunStore,
    run_id: str,
    clock: ClockProvider | None = None,
) -> AcquisitionResult:
    """Collect every immediate native binding or return a failed disposition.

    The full-run Kali transcript is deliberately excluded here. Its admitted
    sidecar remains active until teardown and is finalized by the stop path.
    """

    if not isinstance(run_store, LocalRunStore):
        raise TypeError("native evidence requires a local run store")
    bindings = _native_bindings(plan)
    _persist_capture_plan(plan, run_store, run_id)
    owner = TechVaultNativeEvidenceOwner(
        backend=backend,
        realization=realization,
        project_dir=project_dir,
        indexer_auth=indexer_auth,
        thehive_api_key=thehive_api_key,
    )
    sources = owner.sources()
    collectors = {
        binding.registration_id: _OnDemandNativeCollector(
            binding.registration_id,
            sources[binding.registration_id],  # type: ignore[arg-type]
        )
        for binding in bindings
        if binding.registration_id in sources
    }
    return acquire_evidence(
        bindings=bindings,
        collectors=collectors,
        run_store=run_store,
        scope=RunScope(
            run_id=run_id,
            planned_trial_id=plan.plan_id,
            attempt_id="provisioning",
        ),
        clock=clock or SystemClockProvider(),
    )


__all__ = (
    "NATIVE_TECHVAULT_REGISTRATIONS",
    "TRANSCRIPT_REGISTRATION",
    "acquire_native_evidence",
    "finalize_active_transcript_authority",
    "load_active_transcript_authorities",
    "persist_active_transcript_authority",
)
