"""Append-safe run-discovery index (EXP-009 / ADR-050 "The local index is a
derived recovery journal").

The index is NOT portable truth and never duplicates task, apparatus, parameter,
result, evidence, or provenance fields. It holds bounded *routing facts* only, so
discovery is fast and restart-safe without scanning or trusting arbitrary
filesystem paths.

Publication uses a prepared/committed protocol under a store-owned lock: a
``prepared`` entry names the exact expected manifest/seal identity before the
seal marker is committed; a ``committed`` entry follows it. After a crash the
reader reconciles a prepared entry by validating its one attempt path — the
complete on-disk seal marker AND the sealed manifest it commits — never a
filesystem crawl. A partial trailing append is recovered; a corrupt line in the
middle, a conflicting event, or a marker that does not match its sealed manifest
is surfaced as :class:`IndexCorruptionError` rather than silently trusted.

Every index-directory access is descriptor-relative and no-follow (an
attacker-swapped ``index`` symlink cannot redirect the journal or lock), the
journal append is durable and write-complete, and a rebuild replaces the journal
atomically under the lock.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows has no POSIX flock
    fcntl = None  # type: ignore[assignment]

from aptl.core.archival.layout import (
    INDEX_DIR,
    INDEX_JOURNAL_NAME,
    INDEX_LOCK_NAME,
)
from aptl.core.archival.verify import SealVerificationError, verify_sealed_archive
from aptl.core.runstore import _validate_id, _validate_relative_path
from aptl.utils.logging import get_logger
from aptl.utils.pathsafe import (
    PathContainmentError,
    open_dir_contained_nofollow,
    write_all,
)

log = get_logger("archival.index")

_EVENT_PREPARED = "prepared"
_EVENT_COMMITTED = "committed"
_EVENTS = frozenset({_EVENT_PREPARED, _EVENT_COMMITTED})

_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Bounds keep a malicious or corrupt journal from forcing unbounded work.
_MAX_LINE_BYTES = 4096
_MAX_VERSION = 64
_MAX_SEAL_STATE = 32
_MAX_TERMINAL_AT = 40
_MAX_LOCATION = 256

_FIELD_ORDER = (
    "run_id",
    "run_version",
    "manifest_digest",
    "seal_state",
    "terminal_at",
    "location",
)

_UNSEALED_REASONS = frozenset({"not_found", "base_dir_unavailable"})


class IndexCorruptionError(RuntimeError):
    """Raised when the on-disk journal or a referenced seal marker is corrupt.

    A corrupt middle line, an oversized line, a conflicting event for one run, an
    incomplete/forged seal marker, or a marker whose digest does not match its
    sealed manifest are all corruption — never silently ignored. Only a partial
    trailing append has the narrow recovery rule.
    """


@dataclass(frozen=True)
class IndexEntry:
    """The bounded routing facts recorded for one sealed attempt.

    ``manifest_digest`` is the ``sha256:<hex>`` digest of the canonical run
    record; ``location`` is the run-relative POSIX path of that record.
    """

    run_id: str
    run_version: str
    manifest_digest: str
    seal_state: str
    terminal_at: str
    location: str


def _require(condition: bool, message: str, *, error: type[Exception]) -> None:
    """Raise ``error(message)`` unless ``condition`` holds."""
    if not condition:
        raise error(message)


def _validate_entry(entry: IndexEntry, *, error: type[Exception]) -> None:
    """Validate an entry's routing facts, raising ``error`` on any violation."""
    _require(isinstance(entry, IndexEntry), "entry must be an IndexEntry", error=error)
    try:
        _validate_id(entry.run_id, "run_id")
        _validate_relative_path(entry.location)
    except ValueError as exc:
        raise error(str(exc)) from exc
    _require(
        isinstance(entry.manifest_digest, str)
        and bool(_PREFIXED_SHA256_RE.fullmatch(entry.manifest_digest)),
        f"manifest_digest must be sha256:<64 hex>: {entry.manifest_digest!r}",
        error=error,
    )
    _require(
        isinstance(entry.run_version, str) and 0 < len(entry.run_version) <= _MAX_VERSION,
        "run_version must be a bounded non-empty string",
        error=error,
    )
    _require(
        isinstance(entry.seal_state, str) and 0 < len(entry.seal_state) <= _MAX_SEAL_STATE,
        "seal_state must be a bounded non-empty string",
        error=error,
    )
    _require(
        isinstance(entry.terminal_at, str) and 0 < len(entry.terminal_at) <= _MAX_TERMINAL_AT,
        "terminal_at must be a bounded non-empty string",
        error=error,
    )
    _require(
        len(entry.location) <= _MAX_LOCATION,
        "location exceeds the maximum length",
        error=error,
    )


def _split_complete_lines(raw: bytes) -> list[bytes]:
    """Return the newline-terminated complete lines, dropping a torn tail.

    A journal that does not end in a newline has a partial trailing append (a
    crash mid-write); that final segment is the ONLY line allowed to be dropped
    (ADR-050). Everything before it is a complete, committed line.
    """
    if not raw:
        return []
    return raw.split(b"\n")[:-1]


class DiscoveryIndex:
    """A store-owned, append-safe journal of sealed attempts under ``base_dir``."""

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = Path(base_dir).resolve()

    # -- publication -------------------------------------------------------

    def prepare(self, entry: IndexEntry) -> None:
        """Append a ``prepared`` entry naming the expected seal identity."""
        self._append(_EVENT_PREPARED, entry)

    def commit(self, entry: IndexEntry) -> None:
        """Append a ``committed`` entry after the seal marker is durable."""
        self._append(_EVENT_COMMITTED, entry)

    def _append(self, event: str, entry: IndexEntry) -> None:
        _validate_entry(entry, error=ValueError)
        line = self._render_line(event, entry)
        with self._locked() as dir_fd:
            fd = os.open(
                INDEX_JOURNAL_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)

    @staticmethod
    def _render_line(event: str, entry: IndexEntry) -> bytes:
        payload = {"event": event, **asdict(entry)}
        # Compact, sorted-key JSON keeps identical events byte-identical so a
        # replay dedupes cleanly.
        line = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(line) + 1 > _MAX_LINE_BYTES:
            raise ValueError("index entry exceeds the maximum line size")
        return line + b"\n"

    # -- discovery ---------------------------------------------------------

    def discover(self) -> list[IndexEntry]:
        """Return the sealed attempts, in first-seen journal order.

        A committed entry must be backed by a complete, matching on-disk seal
        marker AND its sealed manifest; a prepared-only entry is reconciled as
        sealed only when its marker is present and valid (crash between seal
        commit and committed append). Inconsistencies raise
        :class:`IndexCorruptionError`.
        """
        sealed: list[IndexEntry] = []
        for run_id, committed, prepared in self._reconcile():
            entry = committed or prepared
            # a run only appears if it has an event
            assert entry is not None
            is_sealed = self._verify_seal(run_id, entry)
            if committed is not None:
                if not is_sealed:
                    raise IndexCorruptionError(
                        f"committed index entry for {run_id!r} is not backed by a "
                        "valid seal marker"
                    )
                sealed.append(committed)
            elif is_sealed:
                sealed.append(prepared)  # recovered
        return sealed

    def recovery_candidates(self) -> list[IndexEntry]:
        """Return prepared attempts whose seal marker is absent (crashed pre-seal)."""
        candidates: list[IndexEntry] = []
        for run_id, committed, prepared in self._reconcile():
            if committed is None and not self._verify_seal(run_id, prepared):
                candidates.append(prepared)
        return candidates

    def rebuild(self, entries: Sequence[IndexEntry]) -> None:
        """Rebuild the journal from validated sealed attempts (explicit repair).

        Each entry must be backed by a complete, matching on-disk seal marker;
        the journal is replaced atomically (write a temp, fsync, rename over the
        journal under the lock) with one committed line per verified attempt.
        Losing the index never changes the portable record or seal.
        """
        verified: list[bytes] = []
        for entry in entries:
            _validate_entry(entry, error=ValueError)
            if not self._verify_seal(entry.run_id, entry):
                raise ValueError(
                    f"cannot rebuild {entry.run_id!r}: seal marker missing or mismatched"
                )
            verified.append(self._render_line(_EVENT_COMMITTED, entry))
        payload = b"".join(verified)
        with self._locked() as dir_fd:
            tmp_name = f".{INDEX_JOURNAL_NAME}.{os.getpid()}.tmp"
            self._atomic_replace_journal(dir_fd, tmp_name, payload)

    @staticmethod
    def _atomic_replace_journal(dir_fd: int, tmp_name: str, payload: bytes) -> None:
        """Write ``payload`` to a temp file and atomically rename it over the journal."""
        # Start from a clean temp name (a crashed predecessor may have left one).
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp_name, INDEX_JOURNAL_NAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)

    # -- internals ---------------------------------------------------------

    def _reconcile(self) -> list[tuple[str, IndexEntry | None, IndexEntry | None]]:
        """Group parsed journal events per run, in first-seen order.

        Returns ``(run_id, committed_entry_or_None, prepared_entry_or_None)``.
        Conflicting facts for one run (or prepared/committed disagreement) raise
        :class:`IndexCorruptionError`.
        """
        order: list[str] = []
        states: dict[str, dict[str, IndexEntry | None]] = {}
        for event, entry in self._parse_journal():
            state = states.get(entry.run_id)
            if state is None:
                state = {_EVENT_PREPARED: None, _EVENT_COMMITTED: None}
                states[entry.run_id] = state
                order.append(entry.run_id)
            existing = state[event]
            if existing is not None and existing != entry:
                raise IndexCorruptionError(
                    f"conflicting {event} entries for run {entry.run_id!r}"
                )
            state[event] = entry
        result = []
        for run_id in order:
            state = states[run_id]
            committed = state[_EVENT_COMMITTED]
            prepared = state[_EVENT_PREPARED]
            if committed is not None and prepared is not None and committed != prepared:
                raise IndexCorruptionError(
                    f"prepared and committed entries for {run_id!r} disagree"
                )
            result.append((run_id, committed, prepared))
        return result

    def _parse_journal(self) -> list[tuple[str, IndexEntry]]:
        raw = self._read_journal_bytes()
        return [self._parse_line(line) for line in _split_complete_lines(raw)]

    @staticmethod
    def _parse_line(line: bytes) -> tuple[str, IndexEntry]:
        if len(line) + 1 > _MAX_LINE_BYTES:
            raise IndexCorruptionError("index journal line exceeds the maximum size")
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IndexCorruptionError(f"corrupt index journal line: {exc}") from exc
        if not isinstance(payload, dict):
            raise IndexCorruptionError("index journal line is not an object")
        event = payload.get("event")
        if event not in _EVENTS:
            raise IndexCorruptionError(f"unknown index event: {event!r}")
        missing = [key for key in _FIELD_ORDER if key not in payload]
        if missing:
            raise IndexCorruptionError(f"index entry missing fields: {missing}")
        extra = set(payload) - {"event", *_FIELD_ORDER}
        if extra:
            raise IndexCorruptionError(f"index entry has unexpected fields: {sorted(extra)}")
        entry = IndexEntry(**{key: payload[key] for key in _FIELD_ORDER})
        _validate_entry(entry, error=IndexCorruptionError)
        return event, entry

    def _read_journal_bytes(self) -> bytes:
        try:
            dir_fd = open_dir_contained_nofollow(self._base_dir, INDEX_DIR, create=False)
        except PathContainmentError as exc:
            if exc.reason in _UNSEALED_REASONS:
                return b""
            raise
        try:
            fd = os.open(
                INDEX_JOURNAL_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd
            )
        except FileNotFoundError:
            return b""
        finally:
            os.close(dir_fd)
        try:
            chunks = []
            while chunk := os.read(fd, 65536):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _verify_seal(self, run_id: str, entry: IndexEntry) -> bool:
        """Return whether ``run_id`` carries a complete, intact seal matching ``entry``.

        Delegates to the canonical :func:`verify_sealed_archive`, which validates
        the marker shape/identity, the manifest digest, AND every inventory
        artifact's size and checksum — so a run whose sealed evidence was
        replaced after the marker is corruption, not a discoverable "sealed" run.
        A missing marker is an unsealed recovery candidate (``False``).
        """
        try:
            verified = verify_sealed_archive(self._base_dir, run_id)
        except SealVerificationError as exc:
            raise IndexCorruptionError(str(exc)) from exc
        if verified is None:
            return False
        if verified.run_record_digest != entry.manifest_digest:
            raise IndexCorruptionError(
                f"index entry for {run_id!r} disagrees with its seal marker"
            )
        return True

    def _locked(self) -> "_JournalLock":
        return _JournalLock(self._base_dir)


class _JournalLock:
    """Exclusive cross-process lock over the discovery journal (fcntl.flock).

    Opens the index directory descriptor-relative and no-follow, so every
    subsequent journal/lock/temp operation is confined even if an attacker swaps
    the ``index`` component for a symlink. Yields the index directory descriptor
    for the caller's openat operations.
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._dir_fd: int | None = None
        self._lock_fd: int | None = None

    def __enter__(self) -> int:
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._dir_fd = open_dir_contained_nofollow(self._base_dir, INDEX_DIR, create=True)
        self._lock_fd = os.open(
            INDEX_LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self._dir_fd,
        )
        if fcntl is not None:  # in-process only without POSIX flock (Windows)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        return self._dir_fd

    def __exit__(self, *_exc: object) -> None:
        if self._lock_fd is not None:
            if fcntl is not None:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None


def rebuild_from_iterable(base_dir: Path, entries: Iterable[IndexEntry]) -> None:
    """Convenience wrapper: rebuild ``base_dir``'s journal from ``entries``."""
    DiscoveryIndex(base_dir).rebuild(list(entries))
