"""CLI command ``aptl doctor``: check prerequisites before a lab start (#1218)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from aptl.cli._common import emit_json_result, exit_status

if TYPE_CHECKING:
    from aptl.core.doctor import DoctorReport

# Failures and warnings stand out in the left column; the words match the
# stable check status values.
_STATUS_LABELS = {"pass": "pass", "warn": "WARN", "fail": "FAIL", "skip": "skip"}


def doctor(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Print the result as one JSON object.",
    ),
) -> None:
    """Check the host and Docker runtime before a lab start. Changes nothing.

    Exit status: 0 when no check failed (warnings are allowed), 1 when at
    least one check failed, 2 for invalid options.
    """
    from aptl.core.doctor import run_doctor

    report = run_doctor(project_dir)
    if output_json:
        emit_json_result("doctor", report.ok, doctor_result_fields(report))
    else:
        render_doctor_report(report)
    raise exit_status(report.ok)


def doctor_result_fields(report: DoctorReport) -> dict[str, object]:
    """Return the ``--json`` fields; they carry what the text lines show."""
    from aptl.core.doctor import CheckStatus

    return {
        "counts": {status.value: report.count(status) for status in CheckStatus},
        "checks": [
            {
                "id": check.check_id,
                "status": check.status.value,
                "summary": check.summary,
                "fix": check.fix,
            }
            for check in report.checks
        ],
    }


def render_doctor_report(report: DoctorReport) -> None:
    """Print one line per check, with the fix under each unmet one."""
    from aptl.core.doctor import CheckStatus

    warnings = report.count(CheckStatus.WARNING)
    counts = ", ".join(
        (
            f"{report.count(CheckStatus.PASSED)} passed",
            f"{warnings} warning" + ("" if warnings == 1 else "s"),
            f"{report.count(CheckStatus.FAILED)} failed",
            f"{report.count(CheckStatus.SKIPPED)} skipped",
        )
    )
    typer.echo(f"aptl doctor: {len(report.checks)} checks ({counts}).")
    width = max((len(check.check_id) for check in report.checks), default=0)
    for check in report.checks:
        label = _STATUS_LABELS[check.status.value]
        typer.echo(f"  {label}  {check.check_id.ljust(width)}  {check.summary}")
        if check.fix:
            typer.echo(f"        fix: {check.fix}")
    typer.echo(
        "No prerequisite failed." if report.ok else "Fix each FAIL, then run it again."
    )
