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
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, TypedDict

import rfc8785

from aptl.utils.logging import get_logger
from aptl.utils.pathsafe import create_exclusive_nofollow, read_contained_nofollow
from aptl.utils.redaction import redact

log = get_logger("runstore")


class SecretInvariantError(ValueError):
    """Raised by :meth:`LocalRunStore.create_json_once` when applying the
    shared secret-classification policy (:mod:`aptl.utils.redaction`) would
    change the payload.

    ADR-047 "Persistence and state model": the create-once operation must
    preserve semantic bytes exactly. It must never silently persist a
    payload that differs from what was approved for execution, so a
    payload containing identity-bearing secret-shaped content is rejected
    outright rather than redacted-and-written.
    """


class RunStoreConflictError(ValueError):
    """Raised by the create-once persistence paths (``create_json_once`` and
    the run-scoped / content-addressed extensions in
    :mod:`aptl.core.evidence.content_store`) when the target already exists
    with bytes that differ from those being written.

    A byte-identical existing payload is treated as idempotent success
    (ADR-047); only a genuine mismatch is an error.
    """


# OBS-003: run / session identifiers become directory components, so they
# must be filesystem-safe. ``trace_id`` from ``trace-context.json`` is hex
# (matches the pattern by construction), but ``session_id`` is produced
# by the MCP server and could in principle drift. Reject anything that
# could break out of the runs/ tree.
# Allow leading `_` so the `_unbound` sentinel (used when MCP servers run
# outside an active scenario context) survives validation. No traversal
# vector — `_` is just a filename character. `\w` is `[A-Za-z0-9_]`
# (SonarCloud S6353 — concise character class).
_ID_RE = re.compile(r"^\w[\w.-]*$")


def _validate_id(value: str, kind: str) -> str:
    """Reject anything that could break out of the ``runs/`` tree.

    Returns the value unchanged when it matches the canonical id
    contract (``^\\w[\\w.-]*$`` AND does not contain ``..``); raises
    ``ValueError`` otherwise. ``kind`` is included in the error
    message so callers see e.g. ``invalid trace_id: '../escape'``.
    """
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"invalid {kind}: {value!r}")
    if ".." in value:
        # `..` survives the character-class regex (dots are allowed for
        # e.g. semantic-version-shaped ids) but is the canonical
        # path-traversal segment. Reject defensively.
        raise ValueError(f"invalid {kind} (contains '..'): {value!r}")
    return value


def _validate_relative_path(relative_path: str) -> str:
    """Reject relative paths that could escape a run directory."""
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError(f"invalid relative_path: {relative_path!r}")
    if Path(relative_path).is_absolute():
        raise ValueError(f"invalid relative_path (absolute): {relative_path!r}")
    parts = PurePosixPath(relative_path.replace("\\", "/")).parts
    if ".." in parts:
        raise ValueError(
            f"invalid relative_path (contains '..'): {relative_path!r}"
        )
    return relative_path


def _canonicalize_payload(payload: object) -> tuple[bytes, object]:
    """Return ``(RFC 8785 canonical bytes, JSON-round-tripped structure)``
    for :meth:`LocalRunStore.create_json_once`.

    The round-tripped structure is what is actually compared and
    persisted: a tuple normalizes to a list, and any value that is not
    already JSON-serializable is a caller bug, not something to silently
    stringify — ``create_json_once`` payloads are structured plan/trial
    projections, not free-form archive data, so (unlike :func:`_safe_default`
    below) no ``default=str`` escape hatch is offered here.
    """
    try:
        raw = json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"create_json_once payload is not JSON-serializable: {exc}") from exc
    normalized = json.loads(raw)
    return rfc8785.dumps(normalized), normalized


def _assert_no_secret_drift(normalized: object) -> None:
    """Reject ``normalized`` if the shared :func:`redact` policy would
    change it at all (ADR-047 create-once secret invariant).

    Reuses the exact production :func:`redact` — the same classification
    :func:`aptl.utils.redaction.is_sensitive_key` and
    :func:`aptl.utils.redaction.is_secret_shaped_value` are built from — so
    this can never silently drift out of lockstep with what actually gets
    redacted elsewhere.
    """
    if redact(normalized) != normalized:
        raise SecretInvariantError(
            "create_json_once payload contains identity-bearing content "
            "the shared secret-classification policy (aptl.utils.redaction) "
            "would change; rejecting rather than silently persisting a "
            "payload that differs from what was approved for execution"
        )


def _safe_default(obj: object) -> str:
    """``json.dumps`` ``default`` hook that stringifies AND redacts.

    Plain ``default=str`` would let any non-JSON-serializable value
    (an exception, a custom object, a ``Path`` whose ``__str__``
    contains an unexpected token) reach disk after :func:`redact`
    has already returned the structure — bypassing the redaction
    contract. Routing the produced string back through ``redact``
    closes that escape hatch (ADR-029).
    """
    return redact(str(obj))


class RunManifest(TypedDict):
    """Metadata manifest for a single experiment run."""

    run_id: str
    scenario_id: str
    scenario_name: str
    started_at: str
    finished_at: str
    duration_seconds: float
    trace_id: str
    config_snapshot: dict[str, Any]
    containers: list[str]
    flags_captured: int


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

    def write_file(self, run_id: str, relative_path: str, data: bytes) -> None:
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

    def copy_file(self, run_id: str, relative_path: str, source: Path) -> None:
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


# ---------------------------------------------------------------------------
# OBS-003: cross-process run-dir resolution.
# ---------------------------------------------------------------------------


def resolve_active_run_dir(state_dir: Path) -> Path | None:
    """Resolve the active scenario's run directory from ``trace-context.json``.

    ``state_dir`` is the APTL state directory (typically ``.aptl/`` at
    the repo root, or wherever ``APTL_STATE_DIR`` points). The function
    reads ``state_dir/trace-context.json`` (the same file the MCP
    servers read for trace correlation) and returns
    ``state_dir/runs/<trace_id>``.

    Returns ``None`` cleanly when:
    - the trace-context file is absent (no scenario active),
    - the file is malformed JSON,
    - the file is missing ``trace_id``, or
    - ``trace_id`` contains characters that could break out of the
      ``runs/`` tree (defence in depth — Python writes hex; this
      catches a tampered file).

    Callers decide what to do with ``None`` (write to an ``_unbound``
    sentinel, skip capture, or log).
    """
    ctx_file = state_dir / "trace-context.json"
    if not ctx_file.exists():
        return None
    # Single return on the failure path (SonarCloud S1142 — at most
    # 3 returns per function): build a `resolved` local and let
    # every error branch fall through to the final `return None`.
    resolved: Path | None = None
    try:
        data = json.loads(ctx_file.read_text(encoding="utf-8"))
        trace_id = data.get("trace_id") if isinstance(data, dict) else None
        if isinstance(trace_id, str):
            try:
                _validate_id(trace_id, "trace_id")
                resolved = state_dir / "runs" / trace_id
            except ValueError:
                log.warning("trace-context.json contained unsafe trace_id; ignoring")
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("trace-context.json unreadable: %s", exc)
    return resolved
