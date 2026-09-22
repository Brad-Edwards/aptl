"""TechVault restart-safe transcript binding and broker-export parsing."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass

from aptl.core.evidence.adapters.sources import SourceResult, _to_outcome
from aptl_techvault.evidence.techvault import (
    RedteamSessionTranscriptSource,
    TranscriptFrame,
    TranscriptSession,
)
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome
from aptl.core.experiment.capture_registry import (
    CaptureBinding,
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistry,
)
from aptl_techvault.capture_registrations import BUILTIN_REGISTRATIONS

_TECHVAULT_REGISTRY = CollectorRegistry(BUILTIN_REGISTRATIONS)

TRANSCRIPT_REGISTRATION = "aptl.collector.redteam-session-transcript"


@dataclass(frozen=True)
class OnDemandHandle:
    """Collector context plus the authority's original activation instant."""

    context: CollectorContext
    started_at: str


def binding_from_projection(value: object) -> CaptureBinding:
    """Rebuild and revalidate one create-once transcript binding projection."""

    data = _binding_projection_data(value)
    limits = _binding_limits(data)
    _normalize_binding_projection(data)
    binding = CaptureBinding(**data, limits=limits)  # type: ignore[arg-type]
    if binding.registration_id != TRANSCRIPT_REGISTRATION:
        raise ValueError("active authority is not a transcript binding")
    if not _registration_pin_matches(binding):
        raise ValueError("transcript registration no longer matches its pin")
    return binding


def _binding_projection_data(value: object) -> dict[str, object]:
    """Require the exact create-once binding projection field set."""

    if not isinstance(value, Mapping):
        raise ValueError("transcript binding is not an object")
    data = dict(value)
    if set(data) != set(_binding_schema_keys()):
        raise ValueError("transcript binding fields do not match the schema")
    return data


def _binding_limits(data: dict[str, object]) -> CaptureLimits:
    """Pop and validate all positive integer capture limits."""

    keys = ("max_bytes", "max_artifact_count", "max_duration_s")
    if any(
        not isinstance(data[key], int) or isinstance(data[key], bool) or data[key] < 1  # type: ignore[operator]
        for key in keys
    ):
        raise ValueError("transcript binding limit is invalid")
    return CaptureLimits(
        max_bytes=data.pop("max_bytes"),  # type: ignore[arg-type]
        max_artifact_count=data.pop("max_artifact_count"),  # type: ignore[arg-type]
        max_duration_s=data.pop("max_duration_s"),  # type: ignore[arg-type]
    )


def _normalize_binding_projection(data: dict[str, object]) -> None:
    """Validate scalars and normalize sequence/enum fields for reconstruction."""

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


def _registration_pin_matches(binding: CaptureBinding) -> bool:
    """Compare the persisted binding to the current exact registration pin."""

    registrations = {
        item.registration_id: item for item in _TECHVAULT_REGISTRY.registrations
    }
    registration = registrations.get(binding.registration_id)
    return bool(
        registration is not None
        and registration.effective_config_digest() == binding.effective_config_digest
        and registration.implementation_version == binding.implementation_version
        and registration.contract_version == binding.contract_version
        and registration.limits == binding.limits
        and registration.visibility_class is binding.visibility_class
    )


def _binding_schema_keys() -> tuple[str, ...]:
    """Return the exact create-once binding projection field set."""

    registration = next(
        item
        for item in _TECHVAULT_REGISTRY.registrations
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


@dataclass
class _TranscriptBudget:
    """Mutable counters enforcing aggregate transcript export limits."""

    limits: CaptureLimits
    retained_bytes: int = 0
    artifact_count: int = 0

    def add_frame(self, decoded: bytes) -> None:
        """Account for one frame or reject before the export can exceed limits."""

        self.retained_bytes += len(decoded) + 256
        self.artifact_count += 1
        if (
            self.retained_bytes > self.limits.max_bytes
            or self.artifact_count > self.limits.max_artifact_count
        ):
            raise ValueError("capture export exceeds admitted limits")


def transcript_sessions(
    payload: object,
    limits: CaptureLimits,
) -> tuple[tuple[str, ...], tuple[TranscriptSession, ...]]:
    """Parse a complete bounded broker export into typed transcript sessions."""

    if not isinstance(payload, Mapping):
        raise ValueError("capture export is not an object")
    expected = _expected_session_ids(payload.get("expected_session_ids"), limits)
    sessions_raw = payload.get("sessions")
    if not isinstance(sessions_raw, list):
        raise ValueError("capture export is incomplete")
    budget = _TranscriptBudget(limits, artifact_count=2 * len(expected))
    sessions = tuple(_transcript_session(raw, budget) for raw in sessions_raw)
    return expected, sessions


def _expected_session_ids(
    expected_raw: object, limits: CaptureLimits
) -> tuple[str, ...]:
    """Validate the exact unique expected-session census."""

    if (
        not isinstance(expected_raw, list)
        or len(expected_raw) > limits.max_artifact_count // 2
        or any(not isinstance(value, str) or not value for value in expected_raw)
    ):
        raise ValueError("capture session inventory is invalid")
    expected = tuple(expected_raw)
    if len(expected) != len(set(expected)):
        raise ValueError("capture session inventory has duplicates")
    return expected


def _transcript_session(raw: object, budget: _TranscriptBudget) -> TranscriptSession:
    """Parse one complete session and account for all of its frames."""

    if not isinstance(raw, Mapping) or not isinstance(raw.get("frames"), list):
        raise ValueError("capture session is incomplete")
    frames = tuple(_transcript_frame(item, budget) for item in raw["frames"])
    loss_count = raw.get("loss_count", 0)
    if not isinstance(loss_count, int) or isinstance(loss_count, bool):
        raise ValueError("capture loss count is invalid")
    return TranscriptSession(
        session_id=str(raw["session_id"]),
        started_at=str(raw["started_at"]),
        finished_at=str(raw["finished_at"]),
        close_reason=str(raw["close_reason"]),
        frames=frames,
        final_chain_digest=str(raw["final_chain_digest"]),
        loss_count=loss_count,
    )


def _transcript_frame(raw: object, budget: _TranscriptBudget) -> TranscriptFrame:
    """Decode one bounded base64 frame and account for its retained bytes."""

    if not isinstance(raw, Mapping):
        raise ValueError("capture frame is not an object")
    sequence = raw.get("sequence")
    encoded = raw.get("data_b64")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not isinstance(encoded, str)
        or len(encoded) > 4 * 1024 * 1024 // 3 + 4
    ):
        raise ValueError("capture frame is invalid")
    decoded = base64.b64decode(encoded, validate=True)
    budget.add_frame(decoded)
    return TranscriptFrame(
        sequence=sequence,
        timestamp=str(raw["timestamp"]),
        direction=str(raw["direction"]),
        data=decoded,
    )


class FinalizedTranscriptCollector:
    """Adapt one already-quiesced broker export to the collector protocol."""

    def __init__(
        self,
        binding: CaptureBinding,
        payload: object,
        activated_at: str,
    ) -> None:
        """Bind the persisted authority, export, and original activation time."""

        self._binding = binding
        self._payload = payload
        self._activated_at = activated_at

    @property
    def registration_id(self) -> str:
        """Return the exact registration pinned by the authority."""

        return self._binding.registration_id

    def start(self, context: CollectorContext) -> OnDemandHandle:
        """Restore the original full-run acquisition start boundary."""

        return OnDemandHandle(context=context, started_at=self._activated_at)

    def stop(self, handle: OnDemandHandle) -> CollectorOutcome:
        """Validate and project the finalized broker export."""

        finished_at = handle.context.clock.now()
        try:
            expected, sessions = transcript_sessions(
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


__all__ = (
    "FinalizedTranscriptCollector",
    "OnDemandHandle",
    "TRANSCRIPT_REGISTRATION",
    "binding_from_projection",
    "transcript_sessions",
)
