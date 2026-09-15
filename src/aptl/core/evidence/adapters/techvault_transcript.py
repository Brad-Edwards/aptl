"""Complete-session transcript evidence for TechVault's Kali participant."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import CollectorStatus

_UTC_OFFSET = "+00:00"


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

    chunks: list[bytes] = []
    frame_count = 0
    for session in sorted(
        sessions, key=lambda item: (item.started_at, item.session_id)
    ):
        chunks.append(f"=== session {session.session_id} start ===\n".encode())
        for frame in session.frames:
            chunks.append(
                f"[{frame.sequence}:{frame.direction}:{frame.timestamp}] ".encode()
                + frame.data
                + b"\n"
            )
            frame_count += 1
        chunks.append(_session_footer(session))
    return SourceResult(
        status=CollectorStatus.OK if sessions else CollectorStatus.EMPTY_OK,
        chunks=tuple(chunks),
        media_type="text/plain",
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


def _session_footer(session: TranscriptSession) -> bytes:
    """Render one bounded custody footer without changing its wire format."""

    return (
        f"=== session {session.session_id} end close={session.close_reason} "
        f"chain={session.final_chain_digest} ===\n"
    ).encode()


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


def _inside_window(value: object, start_iso: str, end_iso: str) -> bool:
    """Return whether an ISO timestamp lies inside the closed capture window."""

    try:
        instant = datetime.fromisoformat(str(value).replace("Z", _UTC_OFFSET))
        start = datetime.fromisoformat(start_iso.replace("Z", _UTC_OFFSET))
        end = datetime.fromisoformat(end_iso.replace("Z", _UTC_OFFSET))
    except (TypeError, ValueError):
        return False
    return start <= instant <= end


__all__ = (
    "RedteamSessionTranscriptSource",
    "TranscriptFrame",
    "TranscriptSession",
    "transcript_chain_digest",
)
