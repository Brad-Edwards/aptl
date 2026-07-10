"""Rendering helpers for lab lifecycle CLI output."""

import typer

from aptl.core.lab import LabResult
from aptl.core.lab_types import StartupDiagnostic, StartupOutcome


# Headline phrasing per outcome. Values are the same stable wire strings as the
# StartupOutcome enum so an operator (or a parser) can grep for them.
_OUTCOME_HEADLINES: dict[StartupOutcome, str] = {
    StartupOutcome.READY: "Lab is ready.",
    StartupOutcome.DEGRADED_USABLE: (
        "Lab is degraded_usable - telemetry/cosmetic warnings, scenarios "
        "should still run."
    ),
    StartupOutcome.DEGRADED_UNUSABLE: (
        "Lab is degraded_unusable - some capabilities or SSH targets are not reachable."
    ),
    StartupOutcome.FAILED: "Lab start failed.",
}


def render_start_result(result: LabResult) -> None:
    """Print a structured summary of a lab-start result."""
    typer.echo(_OUTCOME_HEADLINES[result.outcome])
    if result.outcome is StartupOutcome.FAILED and result.error:
        typer.echo(f"  error: {result.error}")
    if not result.diagnostics:
        return
    typer.echo(f"  diagnostics ({len(result.diagnostics)}):")
    impacts_in_order = ["readiness", "capability", "telemetry", "cosmetic"]
    grouped: dict[str, list[StartupDiagnostic]] = {}
    for diag in result.diagnostics:
        grouped.setdefault(diag.impact.value, []).append(diag)
    for impact in impacts_in_order:
        for diag in grouped.get(impact, []):
            label = f"{diag.step}/{diag.component}" if diag.component else diag.step
            typer.echo(
                f"    [{diag.impact.value}|{diag.severity.value}] "
                f"{label} - {diag.message}"
            )
            if diag.operator_action:
                typer.echo(f"      action: {diag.operator_action}")
