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
import shutil
from pathlib import Path
from typing import Any, Protocol, TypedDict

from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

log = get_logger("runstore")


def _safe_default(obj: Any) -> str:
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
    config_snapshot: dict
    containers: list[str]
    flags_captured: int


class RunStorageBackend(Protocol):
    """Protocol for run storage backends."""

    def create_run(self, run_id: str) -> Path: ...

    def write_file(self, run_id: str, relative_path: str, data: bytes) -> None: ...

    def write_json(self, run_id: str, relative_path: str, obj: Any) -> None: ...

    def write_jsonl(
        self, run_id: str, relative_path: str, records: list[dict]
    ) -> None: ...

    def append_jsonl(
        self, run_id: str, relative_path: str, records: list[dict]
    ) -> None: ...

    def copy_file(self, run_id: str, relative_path: str, source: Path) -> None: ...

    def list_runs(self) -> list[str]: ...

    def get_run_manifest(self, run_id: str) -> dict: ...

    def get_run_path(self, run_id: str) -> Path: ...


class LocalRunStore:
    """Local filesystem run storage.

    Stores runs under ``<base_dir>/<run_id>/`` with a ``manifest.json``
    at the root of each run directory.
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def create_run(self, run_id: str) -> Path:
        run_dir = self._base_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        log.info("Created run directory: %s", run_dir)
        return run_dir

    def write_file(self, run_id: str, relative_path: str, data: bytes) -> None:
        target = self._base_dir / run_id / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        log.debug("Wrote %d bytes to %s", len(data), target)

    def write_json(self, run_id: str, relative_path: str, obj: Any) -> None:
        # Redact at the persistence boundary (ADR-029) so individual
        # callers do not own the policy and run-archive contents are
        # control-plane-secret-safe by construction. ``default`` runs
        # through redaction too — see :func:`_safe_default`.
        safe = redact(obj)
        data = json.dumps(safe, indent=2, default=_safe_default).encode("utf-8")
        self.write_file(run_id, relative_path, data)

    def write_jsonl(
        self, run_id: str, relative_path: str, records: list[dict]
    ) -> None:
        # Redact each record at the persistence boundary (ADR-029).
        lines = [
            json.dumps(redact(r), separators=(",", ":"), default=_safe_default)
            for r in records
        ]
        data = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
        self.write_file(run_id, relative_path, data)

    def append_jsonl(
        self, run_id: str, relative_path: str, records: list[dict]
    ) -> None:
        """Append ``records`` to a JSONL file, creating it if missing.

        Used for evidence streams that accumulate across multiple
        invocations within one run — e.g. ``continuity-events.jsonl``,
        which would lose earlier audits' evidence under
        :meth:`write_jsonl`'s overwrite semantics.
        """
        if not records:
            return
        target = self._base_dir / run_id / relative_path
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
        target = self._base_dir / run_id / relative_path
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

    def get_run_manifest(self, run_id: str) -> dict:
        manifest_path = self._base_dir / run_id / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"No manifest for run {run_id}")
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    def get_run_path(self, run_id: str) -> Path:
        return self._base_dir / run_id
