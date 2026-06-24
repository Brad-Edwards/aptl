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

from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

log = get_logger("runstore")

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
