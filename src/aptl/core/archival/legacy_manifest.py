"""Version-dispatching run-manifest read adapter (EXP-009 / ADR-050
"Discovery index and migration remain subordinate").

``manifest.json`` becomes the single portable RAES ``experiment-run/v1`` record
for new terminal attempts, but existing ``aptl.run-record/v1|v2`` archives — and
the older flat run-manifest shape — must stay readable through ONE adapter. This
module is that adapter: it dispatches on ``schema_version`` and returns a
normalized :class:`RunSummary` so CLI display, S3 metadata, and export read one
shape without each re-implementing shape detection. It never writes and is never
sealed as a second authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: The canonical portable run record for a new terminal attempt.
RAES_RUN_SCHEMA_VERSION = "experiment-run/v1"

#: Legacy APTL reproducibility-record schemas, retained for read compatibility.
LEGACY_REPRODUCIBILITY_SCHEMAS = frozenset(
    {"aptl.run-record/v1", "aptl.run-record/v2"}
)

_UNKNOWN = "?"


@dataclass(frozen=True)
class RunSummary:
    """A shape-normalized view over any run manifest for display/discovery.

    ``is_raes`` distinguishes the portable RAES record from a legacy
    reproducibility record so a caller that genuinely needs contract-specific
    handling can branch, while the common display fields work for every shape.
    """

    run_id: str
    schema_version: str | None
    is_raes: bool
    scenario_id: str
    scenario_name: str
    started_at: str
    finished_at: str
    status: str
    outcome: str
    containers: list[str]
    duration_seconds: float | None
    flags_captured: int | None


def is_raes_run_record(manifest: object) -> bool:
    """Return whether ``manifest`` is the portable RAES ``experiment-run/v1`` record."""
    return (
        isinstance(manifest, dict)
        and manifest.get("schema_version") == RAES_RUN_SCHEMA_VERSION
    )


def summarize_manifest(manifest: dict) -> RunSummary:
    """Return a normalized :class:`RunSummary` for any supported manifest shape."""
    schema_version = manifest.get("schema_version")
    if schema_version == RAES_RUN_SCHEMA_VERSION:
        return _summarize_raes(manifest)
    if schema_version in LEGACY_REPRODUCIBILITY_SCHEMAS:
        return _summarize_reproducibility(manifest, schema_version)
    return _summarize_flat(manifest, schema_version)


def _summarize_raes(manifest: dict) -> RunSummary:
    snapshot = manifest.get("scenario_snapshot_ref") or {}
    scenario_id = snapshot.get("ref_id", _UNKNOWN)
    started = manifest.get("started_at", _UNKNOWN)
    ended = manifest.get("ended_at", _UNKNOWN)
    return RunSummary(
        run_id=manifest.get("run_id", _UNKNOWN),
        schema_version=RAES_RUN_SCHEMA_VERSION,
        is_raes=True,
        scenario_id=scenario_id,
        scenario_name=scenario_id,  # the RAES record carries no display name
        started_at=started,
        finished_at=ended,
        status=manifest.get("run_status", _UNKNOWN),
        outcome=manifest.get("outcome_status", _UNKNOWN),
        containers=[],
        duration_seconds=_duration(started, ended),
        flags_captured=None,
    )


def _summarize_reproducibility(manifest: dict, schema_version: str | None) -> RunSummary:
    # v2 renamed the contract-identity section ``aces`` -> ``raes``; read either.
    section = manifest.get("raes") or manifest.get("aces") or {}
    scenario = section.get("scenario") or {}
    display = scenario.get("display_name", _UNKNOWN)
    outcome = manifest.get("outcome", _UNKNOWN)
    return RunSummary(
        run_id=manifest.get("run_id", _UNKNOWN),
        schema_version=schema_version,
        is_raes=False,
        scenario_id=display,
        scenario_name=display,
        started_at=manifest.get("started_at", _UNKNOWN),
        finished_at=manifest.get("finished_at", _UNKNOWN),
        status=outcome,
        outcome=outcome,
        containers=[],
        duration_seconds=None,
        flags_captured=None,
    )


def _summarize_flat(manifest: dict, schema_version: str | None) -> RunSummary:
    """Summarize the older flat run-manifest shape (top-level scenario fields)."""
    outcome = manifest.get("outcome", _UNKNOWN)
    return RunSummary(
        run_id=manifest.get("run_id", _UNKNOWN),
        schema_version=schema_version,
        is_raes=False,
        scenario_id=manifest.get("scenario_id", _UNKNOWN),
        scenario_name=manifest.get("scenario_name", _UNKNOWN),
        started_at=manifest.get("started_at", _UNKNOWN),
        finished_at=manifest.get("finished_at", _UNKNOWN),
        status=outcome,
        outcome=outcome,
        containers=list(manifest.get("containers", []) or []),
        duration_seconds=manifest.get("duration_seconds"),
        flags_captured=manifest.get("flags_captured"),
    )


def _duration(started: str, ended: str) -> float | None:
    """Return ended-started seconds when both are parseable RFC3339, else ``None``."""
    start = _parse_rfc3339(started)
    end = _parse_rfc3339(ended)
    if start is None or end is None:
        return None
    return (end - start).total_seconds()


def _parse_rfc3339(value: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
