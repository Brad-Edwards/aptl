"""Adapter-owned complete-session transcript evidence for TechVault."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.utils.redaction import REDACTED, is_sensitive_key, redact

_UTC_OFFSET = "+00:00"
_RETAINED_SCHEMA = "aptl-techvault-transcript/v2"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REF_PATTERN = re.compile(r"terminal-[0-9a-f]{64}\Z")
# The shared scanner skips some command patterns beyond this text length.
# Withhold that direction's frames instead of making a partial safety claim.
_MAX_REDACTION_CONTEXT = 64 * 1024


@dataclass(frozen=True)
class TranscriptFrame:
    """One ordered, directed frame retained by the capture broker."""

    sequence: int
    timestamp: str
    direction: str
    data: bytes


@dataclass(frozen=True)
class TranscriptSession:
    """One complete broker-owned participant session and its custody digest."""

    session_id: str
    started_at: str
    finished_at: str
    close_reason: str
    frames: tuple[TranscriptFrame, ...]
    final_chain_digest: str
    loss_count: int = 0


class RedteamSessionTranscriptSource:
    """Require complete sidecar-owned custody for every admitted session."""

    def __init__(
        self,
        expected_session_ids: Callable[[], Sequence[str] | None],
        read_sessions: Callable[[], Sequence[TranscriptSession] | None],
    ) -> None:
        """Bind the admitted census and bounded transcript readback functions."""

        self._expected_session_ids = expected_session_ids
        self._read_sessions = read_sessions

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        """Validate complete custody and return a bounded transcript result."""

        expected = self._expected_session_ids()
        sessions = self._read_sessions()
        status = _session_failure_status(expected, sessions, start_iso, end_iso)
        if status is not None:
            return SourceResult(status=status)
        return _transcript_result(sessions or (), start_iso, end_iso)


def _session_failure_status(
    expected: Sequence[str] | None,
    sessions: Sequence[TranscriptSession] | None,
    start_iso: str,
    end_iso: str,
) -> CollectorStatus | None:
    """Return the exact failure status, or no status for a valid session set."""

    if expected is None or sessions is None:
        return CollectorStatus.SOURCE_UNAVAILABLE
    invalid_identity = (
        len(expected) != len(set(expected))
        or len(sessions) != len({session.session_id for session in sessions})
        or set(expected) != {session.session_id for session in sessions}
    )
    invalid_session = any(
        not _valid_transcript_session(session, start_iso, end_iso)
        for session in sessions
    )
    return CollectorStatus.MID_RUN_LOSS if invalid_identity or invalid_session else None


def _transcript_result(
    sessions: Sequence[TranscriptSession], start_iso: str, end_iso: str
) -> SourceResult:
    """Render validated sessions and their custody metadata."""

    rendered_sessions: list[dict[str, object]] = []
    frame_count = 0
    for session in sorted(
        sessions, key=lambda item: (item.started_at, item.session_id)
    ):
        rendered_frames: list[dict[str, object]] = []
        safe_data = _retained_frame_data(session.frames)
        for frame, data in zip(session.frames, safe_data, strict=True):
            rendered_frames.append(
                {
                    "sequence": frame.sequence,
                    "timestamp": frame.timestamp,
                    "direction": frame.direction,
                    "data": data,
                }
            )
            frame_count += 1
        terminal_identity = (
            b"aptl.techvault.terminal-ref/v1\0"
            + session.session_id.encode("utf-8")
            + b"\0"
            + session.final_chain_digest.encode("ascii")
        )
        rendered_sessions.append(
            {
                "terminal_ref": "terminal-"
                + hashlib.sha256(terminal_identity).hexdigest(),
                "started_at": session.started_at,
                "finished_at": session.finished_at,
                "close_reason": session.close_reason,
                "source_chain_digest": session.final_chain_digest,
                "frames": rendered_frames,
            }
        )
    payload = {
        "schema_version": "aptl-techvault-transcript/v2",
        "transcript_entries": rendered_sessions,
    }
    return SourceResult(
        status=CollectorStatus.OK if sessions else CollectorStatus.EMPTY_OK,
        chunks=(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),),
        media_type="application/json",
        source_min_time=min((item.started_at for item in sessions), default=start_iso),
        source_max_time=max((item.finished_at for item in sessions), default=end_iso),
        source_pipeline={
            "source_refs": [
                {
                    "ref_kind": "apparatus-context",
                    "ref_id": "apparatus.capture.kali-session-capture",
                }
            ],
            "custody": "sidecar-owned-pty-master-sha256-chain",
            "session_count": len(sessions),
            "frame_count": frame_count,
        },
    )


def _retained_frame_data(frames: Sequence[TranscriptFrame]) -> list[str]:
    """Preserve useful frames while withholding secrets split across reads.

    Frame boundaries are transport artifacts. Scan joined input and output
    streams, then the retained chronological stream. When a joined scan finds
    context that individual frame scans missed, withhold the implicated
    direction; a cross-direction match withholds the entire session.
    """
    raw = [frame.data.decode("utf-8") for frame in frames]
    safe = [str(redact(data)) for data in raw]
    for direction in ("input", "output"):
        indices = [i for i, frame in enumerate(frames) if frame.direction == direction]
        joined = "".join(raw[i] for i in indices)
        if len(joined) > _MAX_REDACTION_CONTEXT or redact(joined) != "".join(
            safe[i] for i in indices
        ):
            for index in indices:
                safe[index] = REDACTED
    retained = "".join(safe)
    if len(retained) > _MAX_REDACTION_CONTEXT or redact(retained) != retained:
        return [REDACTED] * len(frames)
    return safe


def _valid_transcript_session(
    session: TranscriptSession, start_iso: str, end_iso: str
) -> bool:
    """Validate temporal, sequence, encoding, and custody-chain completeness."""

    valid_metadata = (
        bool(session.session_id)
        and not session.loss_count
        and session.close_reason
        in {"clean-exit", "remote-eof", "signal", "forced-teardown"}
        and _inside_window(session.started_at, start_iso, end_iso)
        and _inside_window(session.finished_at, start_iso, end_iso)
    )
    return (
        valid_metadata
        and _valid_transcript_frames(session)
        and _transcript_frames_are_utf8(session.frames)
        and _transcript_chain(session.frames) == session.final_chain_digest
    )


def _valid_transcript_frames(session: TranscriptSession) -> bool:
    """Validate frame order, direction, and session-relative timestamps."""

    return (
        all(frame.sequence == index for index, frame in enumerate(session.frames, 1))
        and all(frame.direction in {"input", "output"} for frame in session.frames)
        and all(
            _inside_window(frame.timestamp, session.started_at, session.finished_at)
            for frame in session.frames
        )
    )


def _transcript_frames_are_utf8(frames: Sequence[TranscriptFrame]) -> bool:
    """Return whether every captured frame is strict UTF-8."""

    valid = True
    try:
        for frame in frames:
            frame.data.decode("utf-8")
    except UnicodeDecodeError:
        valid = False
    return valid


def _transcript_chain(frames: Sequence[TranscriptFrame]) -> str:
    """Build the broker's ordered SHA-256 frame custody chain."""

    chain = bytes(32)
    for frame in frames:
        header = f"{frame.sequence}\0{frame.timestamp}\0{frame.direction}\0".encode()
        chain = hashlib.sha256(chain + header + frame.data).digest()
    return "sha256:" + chain.hex()


def transcript_chain_digest(frames: Sequence[TranscriptFrame]) -> str:
    """Return the custody-chain digest used by the sidecar and source verifier."""

    return _transcript_chain(frames)


def validate_retained_transcript(
    payload: object,
    *,
    expected_entries: int | None = None,
    expected_frames: int | None = None,
) -> None:
    """Check the v2 retained projection, optionally against trusted source counts.

    The source chain authenticates the original frames; it cannot be rebuilt
    from frame data after redaction. The evidence record checksums the retained
    bytes separately.
    """
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "transcript_entries"}
        or payload["schema_version"] != _RETAINED_SCHEMA
        or not isinstance(payload["transcript_entries"], list)
    ):
        raise ValueError("retained transcript shape is invalid")
    entries = payload["transcript_entries"]
    if expected_entries is not None and len(entries) != expected_entries:
        raise ValueError("retained transcript count disagrees with source")
    if expected_entries is not None and expected_entries > 0 and not entries:
        raise ValueError("retained transcript collection is empty")
    frame_count = 0
    refs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "terminal_ref",
            "started_at",
            "finished_at",
            "close_reason",
            "source_chain_digest",
            "frames",
        }:
            raise ValueError("retained transcript entry is invalid")
        if any(is_sensitive_key(key) for key in entry):
            raise ValueError("retained transcript has a sensitive structural key")
        ref = entry["terminal_ref"]
        if not isinstance(ref, str) or not _REF_PATTERN.fullmatch(ref) or ref in refs:
            raise ValueError("retained terminal reference is invalid")
        refs.add(ref)
        if (
            not isinstance(entry["source_chain_digest"], str)
            or not _DIGEST_PATTERN.fullmatch(entry["source_chain_digest"])
            or not isinstance(entry["close_reason"], str)
            or entry["close_reason"]
            not in {"clean-exit", "remote-eof", "signal", "forced-teardown"}
            or not isinstance(entry["started_at"], str)
            or not isinstance(entry["finished_at"], str)
            or not _inside_window(
                entry["started_at"], entry["started_at"], entry["finished_at"]
            )
            or not isinstance(entry["frames"], list)
        ):
            raise ValueError("retained transcript metadata is invalid")
        for index, frame in enumerate(entry["frames"], 1):
            if (
                not isinstance(frame, dict)
                or set(frame) != {"sequence", "timestamp", "direction", "data"}
                or any(is_sensitive_key(key) for key in frame)
                or type(frame["sequence"]) is not int
                or frame["sequence"] != index
                or not isinstance(frame["direction"], str)
                or frame["direction"] not in {"input", "output"}
                or not isinstance(frame["timestamp"], str)
                or not isinstance(frame["data"], str)
                or not _inside_window(
                    frame["timestamp"], entry["started_at"], entry["finished_at"]
                )
            ):
                raise ValueError("retained transcript frame is invalid")
            frame_count += 1
    if expected_frames is not None and frame_count != expected_frames:
        raise ValueError("retained frame count disagrees with source")


def _inside_window(value: object, start_iso: str, end_iso: str) -> bool:
    """Return whether an ISO timestamp lies inside the closed capture window."""

    try:
        instant = datetime.fromisoformat(str(value).replace("Z", _UTC_OFFSET))
        start = datetime.fromisoformat(start_iso.replace("Z", _UTC_OFFSET))
        end = datetime.fromisoformat(end_iso.replace("Z", _UTC_OFFSET))
    except (TypeError, ValueError):
        return False
    try:
        return start <= instant <= end
    except TypeError:
        return False


__all__ = (
    "RedteamSessionTranscriptSource",
    "TranscriptFrame",
    "TranscriptSession",
    "validate_retained_transcript",
    "transcript_chain_digest",
)
