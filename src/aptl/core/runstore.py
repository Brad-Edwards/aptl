"""Run storage for experiment data.

Provides a protocol for storing per-run experiment data and a local
filesystem implementation. Each run is identified by a UUID and
stored in a self-contained directory with all collected artifacts.

This module is the Python persistence serialization boundary for run
archives (ADR-029): structured writes (``write_json`` / ``write_jsonl``
/ ``append_jsonl``) run the shared :func:`aptl.utils.redaction.redact`
helper so control-plane/operator secrets are masked before bytes hit
disk. ``write_file`` (opaque bytes) and ``copy_file`` (arbitrary files)
cannot be structurally redacted and are pass-through by design —
callers must not route control-plane secrets through them.
"""

import json
import os
import shutil
import threading
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Protocol

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows has no POSIX flock
    fcntl = None  # type: ignore[assignment]

from aptl.core.runstore_internals import (
    _LOCK_REGISTRY,
    _LOCK_REGISTRY_GUARD,
    RunManifest,
    RunStoreConflictError,
    SealedRunError,
    SecretInvariantError,
    _assert_no_secret_drift,
    _canonicalize_payload,
    _HeldLock,
    _safe_default,
    _validate_id,
    _validate_relative_path,
    resolve_active_run_dir,
)
from aptl.utils.logging import get_logger
from aptl.utils.pathsafe import (
    REASON_BASE_DIR_UNAVAILABLE,
    REASON_NOT_FOUND,
    PathContainmentError,
    create_exclusive_nofollow,
    open_dir_contained_nofollow,
    read_contained_nofollow,
)
from aptl.utils.redaction import redact

__all__ = [
    "LocalRunStore",
    "RunManifest",
    "RunStorageBackend",
    "RunStoreConflictError",
    "SEAL_MARKER_RELPATH",
    "SealedRunError",
    "SecretInvariantError",
    "resolve_active_run_dir",
]

#: Store-relative directory holding per-attempt finalization locks (store-owned,
#: no-follow). Skipped by ``list_runs`` since it carries no ``manifest.json``.
_LOCKS_DIR = "locks"

#: Run-relative path of the ADR-050 atomic seal marker. Defined here — the store
#: owns seal-state enforcement — and re-exported by
#: :mod:`aptl.core.archival.layout` so the archival package has one source of
#: truth without the store importing the archival package (which would cycle).
SEAL_MARKER_RELPATH = "seal.json"

#: Containment reasons that mean "no seal marker is present" rather than an
#: error: the run directory, or the whole run store, does not exist yet.
_UNSEALED_REASONS = frozenset({REASON_NOT_FOUND, REASON_BASE_DIR_UNAVAILABLE})

log = get_logger("runstore")


class RunStorageBackend(Protocol):
    """Protocol for run storage backends."""

    def create_run(self, run_id: str) -> Path: ...

    def write_file(self, run_id: str, relative_path: str, data: bytes) -> None: ...

    def write_json(self, run_id: str, relative_path: str, obj: object) -> None: ...

    def write_jsonl(
        self, run_id: str, relative_path: str, records: list[dict[str, Any]]
    ) -> None: ...

    def append_jsonl(
        self, run_id: str, relative_path: str, records: list[dict[str, Any]]
    ) -> None: ...

    def create_run_json_once(
        self,
        run_id: str,
        relative_path: str,
        payload: object,
    ) -> Path: ...

    def copy_file(self, run_id: str, relative_path: str, source: Path) -> None: ...

    def create_json_once(self, namespace: str, name: str, payload: object) -> Path: ...

    def list_runs(self) -> list[str]: ...

    def get_run_manifest(self, run_id: str) -> dict[str, Any]: ...

    def get_run_path(self, run_id: str) -> Path: ...


class LocalRunStore:
    """Local filesystem run storage.

    Stores runs under ``<base_dir>/<run_id>/`` with a ``manifest.json``
    at the root of each run directory.
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir.resolve()

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def _run_dir(self, run_id: str) -> Path:
        """Return the resolved run directory after validating ``run_id``."""
        safe_run_id = _validate_id(run_id, "run_id")
        return (self._base_dir / safe_run_id).resolve()

    def _resolve_run_target(self, run_id: str, relative_path: str) -> Path:
        """Resolve a write/read target under ``<base_dir>/<run_id>/``."""
        run_dir = self._run_dir(run_id)
        safe_rel = _validate_relative_path(relative_path)
        target = (run_dir / safe_rel).resolve()
        if not target.is_relative_to(run_dir):
            raise ValueError(
                f"invalid relative_path (escapes run dir): {relative_path!r}"
            )
        return target

    def create_run(self, run_id: str) -> Path:
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        log.info("Created run directory: %s", run_dir)
        return run_dir

    def is_sealed(self, run_id: str) -> bool:
        """Return whether the run's ADR-050 seal marker has been committed.

        Read no-follow: a missing marker (or missing run directory) is
        ``False``; any other containment failure propagates.
        """
        safe_run_id = _validate_id(run_id, "run_id")
        try:
            read_contained_nofollow(
                self._base_dir, f"{safe_run_id}/{SEAL_MARKER_RELPATH}"
            )
        except PathContainmentError as exc:
            if exc.reason in _UNSEALED_REASONS:
                return False
            raise
        return True

    def read_seal_marker(self, run_id: str) -> dict[str, Any] | None:
        """Return the parsed seal marker for ``run_id``, or ``None`` if unsealed."""
        safe_run_id = _validate_id(run_id, "run_id")
        try:
            raw = read_contained_nofollow(
                self._base_dir, f"{safe_run_id}/{SEAL_MARKER_RELPATH}"
            )
        except PathContainmentError as exc:
            if exc.reason in _UNSEALED_REASONS:
                return None
            raise
        return json.loads(raw)

    def commit_seal_marker(self, run_id: str, marker: object) -> Path:
        """Atomically publish the seal marker create-once (the archive commit point).

        This is the ONLY path allowed to write the reserved marker: it holds the
        per-run lock and writes create-once WITHOUT the sealed-state rejection
        (the marker is what makes the run sealed). An identical marker is
        idempotent; a differing marker raises :class:`RunStoreConflictError`.
        Once it returns, every other mutation path refuses.
        """
        with self.finalization_lock(run_id):
            return self._create_run_json_once_raw(run_id, SEAL_MARKER_RELPATH, marker)

    def read_run_json(self, run_id: str, relative_path: str) -> Any | None:
        """Return a parsed run-relative JSON file (no-follow), or ``None`` if absent."""
        safe_run_id = _validate_id(run_id, "run_id")
        safe_rel = _validate_relative_path(relative_path)
        try:
            raw = read_contained_nofollow(self._base_dir, f"{safe_run_id}/{safe_rel}")
        except PathContainmentError as exc:
            if exc.reason in _UNSEALED_REASONS:
                return None
            raise
        return json.loads(raw)

    @contextmanager
    def finalization_lock(self, run_id: str) -> Iterator[None]:
        """Hold the store-owned exclusive per-run lock (reentrant per thread).

        The archival coordinator holds this across compose, verification, and
        marker publication so two finalizers of the same attempt cannot race
        (ADR-050 "per-attempt finalization exclusion"). Every run-directory
        mutation acquires it too, so a producer cannot pass a sealed-state check
        and then interleave a write with the seal commit. Nesting within one
        thread reuses a single ``flock``; a different thread or process blocks
        until release. The lock file lives in a store-owned ``locks/`` directory
        opened descriptor-relative and no-follow, so an attacker-swapped
        ``locks`` symlink cannot redirect it.
        """
        safe_run_id = _validate_id(run_id, "run_id")
        key = (str(self._base_dir), safe_run_id, threading.get_ident())
        with _LOCK_REGISTRY_GUARD:
            held = _LOCK_REGISTRY.get(key)
            if held is not None:
                held.depth += 1
                reused = True
            else:
                reused = False
        if not reused:
            # Without POSIX flock (Windows) the lock is in-process only; the
            # registry still provides per-thread reentrancy + mutual exclusion.
            lock_fd = self._open_run_lock_fd(safe_run_id) if fcntl is not None else -1
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            with _LOCK_REGISTRY_GUARD:
                _LOCK_REGISTRY[key] = _HeldLock(fd=lock_fd, depth=1)
        try:
            yield
        finally:
            with _LOCK_REGISTRY_GUARD:
                entry = _LOCK_REGISTRY[key]
                entry.depth -= 1
                if entry.depth == 0:
                    if fcntl is not None:
                        fcntl.flock(entry.fd, fcntl.LOCK_UN)
                        os.close(entry.fd)
                    del _LOCK_REGISTRY[key]

    def _open_run_lock_fd(self, safe_run_id: str) -> int:
        self._base_dir.mkdir(parents=True, exist_ok=True)
        dir_fd = open_dir_contained_nofollow(self._base_dir, _LOCKS_DIR, create=True)
        try:
            return os.open(
                f"{safe_run_id}.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
        finally:
            os.close(dir_fd)

    def _reject_if_sealed(self, run_id: str, relative_path: str) -> None:
        """Refuse a mutable write to a sealed run or the reserved marker path.

        The seal marker path is reserved from every generic writer (ADR-050 /
        codex security finding): only :meth:`commit_seal_marker` may publish it,
        so a compromised collector or sidecar cannot forge a marker or race the
        seal commit through ``write_json`` / ``append_jsonl`` / ``copy_file``.
        """
        if _validate_relative_path(relative_path).replace("\\", "/") == SEAL_MARKER_RELPATH:
            raise SealedRunError(
                f"{SEAL_MARKER_RELPATH!r} is the reserved seal marker path; only "
                "the seal-commit path may write it"
            )
        if self.is_sealed(run_id):
            raise SealedRunError(
                f"run {run_id!r} is sealed; its archive is immutable — a "
                "correction is a new run version, not an in-place write"
            )

    def write_file(self, run_id: str, relative_path: str, data: bytes) -> None:
        with self.finalization_lock(run_id):
            self._reject_if_sealed(run_id, relative_path)
            target = self._resolve_run_target(run_id, relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            log.debug("Wrote %d bytes to %s", len(data), target)

    def write_json(self, run_id: str, relative_path: str, obj: object) -> None:
        # Redact at the persistence boundary (ADR-029) so individual
        # callers do not own the policy and run-archive contents are
        # control-plane-secret-safe by construction. ``default`` runs
        # through redaction too — see :func:`_safe_default`.
        safe = redact(obj)
        data = json.dumps(safe, indent=2, default=_safe_default).encode("utf-8")
        self.write_file(run_id, relative_path, data)

    def write_jsonl(
        self, run_id: str, relative_path: str, records: list[dict[str, Any]]
    ) -> None:
        # Redact each record at the persistence boundary (ADR-029).
        lines = [
            json.dumps(redact(r), separators=(",", ":"), default=_safe_default)
            for r in records
        ]
        data = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
        self.write_file(run_id, relative_path, data)

    def append_jsonl(
        self, run_id: str, relative_path: str, records: list[dict[str, Any]]
    ) -> None:
        """Append ``records`` to a JSONL file, creating it if missing.

        Used for evidence streams that accumulate across multiple
        invocations within one run — e.g. ``continuity-events.jsonl``,
        which would lose earlier audits' evidence under
        :meth:`write_jsonl`'s overwrite semantics.
        """
        if not records:
            return
        with self.finalization_lock(run_id):
            self._reject_if_sealed(run_id, relative_path)
            target = self._resolve_run_target(run_id, relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Redact each record at the persistence boundary (ADR-029).
            lines = [
                json.dumps(redact(r), separators=(",", ":"), default=_safe_default)
                for r in records
            ]
            chunk = ("\n".join(lines) + "\n").encode("utf-8")
            with open(target, "ab") as fh:
                fh.write(chunk)
            log.debug("Appended %d JSONL records to %s", len(records), target)

    def create_run_json_once(
        self,
        run_id: str,
        relative_path: str,
        payload: object,
    ) -> Path:
        """Atomically publish one immutable, run-scoped JSON artifact.

        Holds the per-run lock and rechecks seal state while holding it, so a
        create-once write cannot add a file to (or forge the marker of) a run
        that is being, or has been, sealed by another writer.
        """
        with self.finalization_lock(run_id):
            self._reject_if_sealed(run_id, relative_path)
            return self._create_run_json_once_raw(run_id, relative_path, payload)

    def _create_run_json_once_raw(
        self, run_id: str, relative_path: str, payload: object
    ) -> Path:
        """The unguarded create-once write (canonical, no-follow, atomic).

        Callers MUST already hold :meth:`finalization_lock` and have applied the
        appropriate sealed-state policy — only :meth:`commit_seal_marker` may use
        it to write the reserved marker.
        """
        safe_run_id = _validate_id(run_id, "run_id")
        safe_relpath = _validate_relative_path(relative_path).replace("\\", "/")
        contained_relpath = f"{safe_run_id}/{safe_relpath}"
        canonical, normalized = _canonicalize_payload(payload)
        _assert_no_secret_drift(normalized)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        target = self._base_dir / safe_run_id / PurePosixPath(safe_relpath)
        try:
            create_exclusive_nofollow(self._base_dir, contained_relpath, canonical)
        except FileExistsError:
            existing = read_contained_nofollow(self._base_dir, contained_relpath)
            if existing != canonical:
                raise RunStoreConflictError(
                    "create_run_json_once target already exists with "
                    f"different content: {safe_relpath}"
                ) from None
        return target

    def copy_file(self, run_id: str, relative_path: str, source: Path) -> None:
        with self.finalization_lock(run_id):
            self._reject_if_sealed(run_id, relative_path)
            target = self._resolve_run_target(run_id, relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            log.debug("Copied %s -> %s", source, target)

    def create_json_once(self, namespace: str, name: str, payload: object) -> Path:
        """Create-once, canonical, no-follow, atomic persistence for a
        controller-owned journal artifact (e.g. a future admitted
        experiment trial plan).

        ADR-047 "Persistence and state model": distinct from the run-id
        run-archive tree (:meth:`write_json`/``_run_dir``) — this targets
        ``<base_dir>/<namespace>/<name>.json``, an explicit non-run
        namespace beneath the injected store root. It never synthesizes a
        ``manifest.json`` and is invisible to :meth:`list_runs`.

        Semantics:
          1. Canonicalize ``payload`` ONCE to RFC 8785 bytes, after a JSON
             round-trip so both the secret-invariant comparison and the
             persisted bytes reflect exactly the same structure (a tuple or
             other non-JSON shape cannot silently disagree with what lands
             on disk).
          2. Secret invariant: if the shared ``redact()`` policy would
             change the canonicalized structure at all, raise
             :class:`SecretInvariantError` — never silently persist a
             payload that differs from what was approved.
          3. Publish with ``O_CREAT | O_EXCL`` under a descriptor-relative,
             no-follow path (:mod:`aptl.utils.pathsafe`), so a pre-existing
             symlink at any path component cannot redirect the write
             outside ``base_dir``.
          4. Idempotent: a target that already exists with byte-identical
             canonical content is a no-op success. Different existing
             bytes raise :class:`RunStoreConflictError`.

        Returns the absolute path written (or already present).
        """
        safe_namespace = _validate_id(namespace, "namespace")
        safe_name = _validate_id(name, "name")
        canonical, normalized = _canonicalize_payload(payload)
        _assert_no_secret_drift(normalized)

        self._base_dir.mkdir(parents=True, exist_ok=True)
        relative_path = f"{safe_namespace}/{safe_name}.json"
        target = self._base_dir / safe_namespace / f"{safe_name}.json"
        try:
            create_exclusive_nofollow(self._base_dir, relative_path, canonical)
        except FileExistsError:
            existing = read_contained_nofollow(self._base_dir, relative_path)
            if existing != canonical:
                raise RunStoreConflictError(
                    "create_json_once target already exists with different "
                    f"content: {namespace}/{name}"
                ) from None
            log.debug("create_json_once idempotent no-op: %s", target)
            return target
        log.info("create_json_once wrote %d bytes to %s", len(canonical), target)
        return target

    def list_runs(self) -> list[str]:
        if not self._base_dir.exists():
            return []
        runs = []
        for child in sorted(self._base_dir.iterdir()):
            if child.is_dir() and (child / "manifest.json").exists():
                runs.append(child.name)
        return runs

    def get_run_manifest(self, run_id: str) -> dict[str, Any]:
        manifest_path = self._resolve_run_target(run_id, "manifest.json")
        if not manifest_path.exists():
            raise FileNotFoundError(f"No manifest for run {run_id}")
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    def get_run_path(self, run_id: str) -> Path:
        return self._run_dir(run_id)

    # ------------------------------------------------------------------
    # OBS-003: per-session subdirectory contract.
    # The directory layout is:
    #   <base>/<run_id>/
    #     mcp-side/
    #       tool-calls.jsonl
    #       ocsf.jsonl
    #       sessions/<session_id>.jsonl    # continuous PTY tee
    #     kali-side/<session_id>/
    #       pty/, pcap/, audit/, proc-acct/
    # ------------------------------------------------------------------

    def mcp_side_dir(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "mcp-side"

    def kali_side_session_dir(self, run_id: str, session_id: str) -> Path:
        return (
            self._run_dir(run_id)
            / "kali-side"
            / _validate_id(session_id, "session_id")
        )

    def mcp_session_jsonl(self, run_id: str, session_id: str) -> Path:
        return (
            self.mcp_side_dir(run_id)
            / "sessions"
            / f"{_validate_id(session_id, 'session_id')}.jsonl"
        )
