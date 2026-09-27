"""TechVault retained per-host enrollment identity readiness is compared against.

Comparing the manager's current view of an agent with that agent's current
`client.keys` proves only that the two agree right now. Delete the retained
identity, let the agent re-enroll, and both sides move together to a new id --
the comparison still passes while every event attributed to the old id has been
orphaned. That is precisely the failure the released scope calls out, so the
comparison needs an identity recorded *before* the restart to compare against.

This module owns that baseline. The first successful observation of a host
records its id; every later observation compares against the recorded one. The
baseline lives under the realization root beside the other backend-owned state,
so it survives the container lifecycle it is there to observe, and the explicit
volume reset that legitimately clears enrollment clears it too.
"""

from __future__ import annotations

import json
from pathlib import Path

from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)

ENROLLMENT_BASELINE_RELPATH = Path(
    ".aptl/realization/wazuh-agent-identity/baseline.json"
)


def enrollment_baseline(scenario_root: Path) -> dict[str, str] | None:
    """Return the baseline, empty when absent and ``None`` when unreadable."""

    result: dict[str, str] | None = None
    try:
        path = _canonical_generated_path(scenario_root, ENROLLMENT_BASELINE_RELPATH)
    except ValueError:
        pass
    else:
        try:
            recorded = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            result = {}
        except (OSError, ValueError):
            pass
        else:
            if _valid_baseline(recorded):
                result = dict(recorded)
    return result


def _valid_baseline(recorded: object) -> bool:
    """Return whether the decoded baseline is a non-empty string mapping."""

    return isinstance(recorded, dict) and all(
        isinstance(node, str)
        and bool(node)
        and isinstance(identifier, str)
        and bool(identifier)
        for node, identifier in recorded.items()
    )


def clear_enrollment_baseline(scenario_root: Path | None) -> list[str]:
    """Forget the recorded identities, returning any failure to do so.

    The baseline only means something relative to the retained state it
    describes. The explicit volume reset removes that state and agents
    legitimately enrol afresh, so a baseline that outlived it would report
    every host as re-enrolled forever. This is called from the same reset, and
    only from there: ordinary stop/start retains both.
    """

    if scenario_root is None:
        return []
    try:
        path = _canonical_generated_path(
            Path(scenario_root), ENROLLMENT_BASELINE_RELPATH
        )
        path.unlink(missing_ok=True)
    except (OSError, ValueError):
        return ["Wazuh enrollment baseline could not be cleared"]
    return []


def record_enrollment_baseline(scenario_root: Path, observed: dict[str, str]) -> bool:
    """Record ids for hosts not yet baselined, never overwriting an existing one.

    An existing entry is deliberately immutable here: overwriting it would erase
    the very evidence a later comparison depends on, turning a lost identity
    into a fresh baseline that passes. The explicit volume reset is the one
    operation that clears it, through :func:`clear_enrollment_baseline`.
    """

    recorded = enrollment_baseline(scenario_root)
    if recorded is None:
        return False
    merged = {**{k: v for k, v in observed.items() if k and v}}
    merged.update(recorded)
    try:
        path = _canonical_generated_path(scenario_root, ENROLLMENT_BASELINE_RELPATH)
        _ensure_secure_dir(path.parent)
        _atomic_write_secure(
            path, json.dumps(merged, sort_keys=True, separators=(",", ":")) + "\n"
        )
    except (OSError, ValueError):
        # A baseline that cannot be written must not be treated as satisfied;
        # the caller sees no recorded identity and reports enrollment unproven.
        return False
    return enrollment_baseline(scenario_root) == merged


__all__ = (
    "ENROLLMENT_BASELINE_RELPATH",
    "clear_enrollment_baseline",
    "enrollment_baseline",
    "record_enrollment_baseline",
)
