"""Post-apply diagnostics and workflow-driving helpers for the RAES backend.

Split out of :mod:`aptl.backends.raes` to keep that module within its size
budget. Both run after ``RuntimeManager.apply`` has returned: one re-attaches
the provisioner's own failure report to an apply whose diagnostics the runtime
boundary masked, the other drives any registered orchestrator workflows. Each
is a leaf — it calls no other function in ``raes.py`` — so ``raes.py`` imports
them one-directionally, with no cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aptl.backends.raes_diagnostics import render_raes_diagnostics
from aptl.backends.raes_orchestrator import AptlOrchestrator
from aptl.core.lab_types import LabResult

if TYPE_CHECKING:
    from raes_contracts.diagnostics import Diagnostic
    from raes_runtime.registry import RuntimeTarget

    from aptl.core.runstore import RunStorageBackend


def _with_backend_failure_diagnostics(
    target: RuntimeTarget,
    diagnostics: list[Diagnostic],
) -> list[Diagnostic]:
    """Re-attach the provisioner's own failure report to a failed apply.

    ``raes_runtime``'s backend-call boundary replaces a failed backend apply's
    diagnostics with its snapshot-contract / SEM-218 gate output — the gate
    evaluates the never-realized snapshot, so every exact declaration reads as
    unrealized. That hides the backend's actionable failure (for example a
    Docker subnet conflict with its remediation steps) and severs the
    retryable-code signal the SOC retry keys on. The backend's own report is
    authoritative for what failed, so it renders first.
    """
    captured = tuple(getattr(target.provisioner, "last_failure_diagnostics", ()))
    if not captured:
        return diagnostics
    seen = {
        (diagnostic.code, diagnostic.address, diagnostic.message)
        for diagnostic in diagnostics
    }
    fresh = [
        diagnostic
        for diagnostic in captured
        if (diagnostic.code, diagnostic.address, diagnostic.message) not in seen
    ]
    return [*fresh, *diagnostics]


def _drive_orchestrator_workflows(
    orchestrator: object,
    evaluation_results: dict[str, dict[str, object]],
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> LabResult | None:
    """Drive registered workflows and convert diagnostics to a lab failure."""

    drive_diagnostics = []
    if isinstance(orchestrator, AptlOrchestrator) and orchestrator.results():
        drive_diagnostics = orchestrator.drive_workflows(
            evaluation_results=evaluation_results,
            run_store=run_store,
            run_id=run_id,
        )
    failure = None
    if drive_diagnostics:
        failure = LabResult(
            success=False,
            error=render_raes_diagnostics(drive_diagnostics),
        )
    return failure
