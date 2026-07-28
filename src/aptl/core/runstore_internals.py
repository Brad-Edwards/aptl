"""Internal helpers and shared state for :mod:`aptl.core.runstore`.

Split out of ``runstore.py`` (which owns the :class:`LocalRunStore` filesystem
implementation) so the module stays focused: this file holds the id/path
validators, the create-once canonicalization + secret-invariant helpers, the
per-run lock registry, the create-once error taxonomy, and the cross-process
run-dir resolution. ``runstore`` re-imports and re-exports these, so existing
``from aptl.core.runstore import ...`` call sites are unaffected.
"""

import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict

import rfc8785

from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

log = get_logger("runstore")


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


@dataclass
class _HeldLock:
    """A held per-run finalization lock: its file descriptor and reentrancy depth."""

    fd: int
    depth: int


#: Process-wide registry of held per-run locks, keyed by
#: ``(base_dir, run_id, thread_id)``. Reentrancy is per THREAD: the same thread
#: nesting acquisitions (a coordinator holding the lock while its create-once
#: manifest write re-acquires it) reuses one ``flock``; a different thread or
#: process opens its own descriptor and blocks on ``flock`` until released. This
#: makes every run-directory mutation mutually exclusive with finalization
#: without the coordinator deadlocking on itself.
_LOCK_REGISTRY: dict[tuple[str, str, int], _HeldLock] = {}
_LOCK_REGISTRY_GUARD = threading.Lock()


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


class SealedRunError(RuntimeError):
    """Raised when a mutable write targets an already-sealed run archive.

    ADR-050 "A seal marker is the atomic commit point": once the run's seal
    marker exists, every structured, opaque, and export path must treat the
    archive as immutable. Overwrite-capable writers refuse rather than mutate
    sealed bytes; a correction is a new run version, never an in-place edit.
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
