"""CLI commands for experiment run management."""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aptl.cli._common import resolve_run_store
from aptl.core.archival.legacy_manifest import summarize_manifest
from aptl.core.runstore import LocalRunStore
from aptl.utils.logging import get_logger

log = get_logger("cli.runs")

app = typer.Typer(help="Experiment run management.")
console = Console()


def _get_store(project_dir: Path) -> LocalRunStore:
    """Initialize a LocalRunStore from project config (thin alias)."""
    return resolve_run_store(project_dir)


def _print_run_table(store: LocalRunStore, run_ids: list[str]) -> None:
    """Render the runs as a rich table (interactive TTY output)."""
    table = Table(title="Experiment Runs")
    table.add_column("Run ID", style="cyan", no_wrap=True)
    table.add_column("Scenario")
    table.add_column("Started")
    table.add_column("Duration")
    table.add_column("Flags")

    for run_id in run_ids:
        try:
            summary = summarize_manifest(store.get_run_manifest(run_id))
            duration = summary.duration_seconds or 0
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            flags = "0" if summary.flags_captured is None else str(summary.flags_captured)
            table.add_row(
                run_id[:12] + "...",
                summary.scenario_name,
                summary.started_at[:19],
                f"{minutes}m {seconds}s",
                flags,
            )
        except (FileNotFoundError, KeyError) as e:
            log.warning("Skipping run %s: %s", run_id, e)
            table.add_row(run_id[:12] + "...", "[red]ERROR[/red]", "", "", "")

    console.print(table)


def _print_run_lines(store: LocalRunStore, run_ids: list[str]) -> None:
    """Render the runs as plain tab-separated lines (non-TTY output)."""
    for run_id in run_ids:
        try:
            summary = summarize_manifest(store.get_run_manifest(run_id))
            typer.echo(
                f"{run_id}\t{summary.scenario_name}\t{summary.started_at[:19]}"
            )
        except (FileNotFoundError, KeyError):
            typer.echo(f"{run_id}\tERROR")


@app.command("list")
def list_runs(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of runs to display.",
    ),
) -> None:
    """List recent experiment runs."""
    store = _get_store(project_dir)
    run_ids = store.list_runs()

    if not run_ids:
        typer.echo("No experiment runs found.")
        return

    # Show most recent first, up to limit
    run_ids = list(reversed(run_ids))[:limit]

    if sys.stdout.isatty():
        _print_run_table(store, run_ids)
    else:
        _print_run_lines(store, run_ids)

    typer.echo(f"\n{len(run_ids)} run(s) shown (of {len(store.list_runs())} total)")


@app.command("show")
def show_run(
    run_id: str = typer.Argument(help="Run UUID (full or prefix)."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Show details of a specific run."""
    store = _get_store(project_dir)
    resolved_id = _resolve_run_id(store, run_id)

    try:
        summary = summarize_manifest(store.get_run_manifest(resolved_id))
    except FileNotFoundError:
        typer.echo(f"Run {resolved_id} has no manifest.")
        raise typer.Exit(code=1)

    duration = summary.duration_seconds or 0
    minutes = int(duration // 60)
    seconds = int(duration % 60)

    typer.echo(f"Run: {resolved_id}")
    typer.echo(f"  Scenario:     {summary.scenario_name}")
    typer.echo(f"  Scenario ID:  {summary.scenario_id}")
    typer.echo(f"  Started:      {summary.started_at}")
    typer.echo(f"  Finished:     {summary.finished_at}")
    typer.echo(f"  Duration:     {minutes}m {seconds}s")
    if summary.status != "?":
        typer.echo(f"  Status:       {summary.status}")
    typer.echo(f"  Flags:        {0 if summary.flags_captured is None else summary.flags_captured}")

    if summary.containers:
        typer.echo(f"  Containers:   {', '.join(summary.containers)}")

    _echo_run_files(store.get_run_path(resolved_id))


@app.command("path")
def run_path(
    run_id: str = typer.Argument(help="Run UUID (full or prefix)."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Print the filesystem path to a run directory."""
    store = _get_store(project_dir)

    all_runs = store.list_runs()
    matches = [r for r in all_runs if r.startswith(run_id)]
    if not matches:
        typer.echo(f"No run found matching '{run_id}'")
        raise typer.Exit(code=1)
    if len(matches) > 1:
        typer.echo(f"Ambiguous run ID '{run_id}', matches: {', '.join(matches[:5])}")
        raise typer.Exit(code=1)

    typer.echo(str(store.get_run_path(matches[0])))


def _format_size(size: int) -> str:
    """Render a byte count as a human-readable size string."""
    if size > 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} MB"
    if size > 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _echo_run_files(run_path: Path) -> None:
    """List the files under a run directory with their sizes."""
    if not run_path.exists():
        return
    typer.echo("")
    typer.echo("Files:")
    for item in sorted(run_path.rglob("*")):
        if item.is_file():
            rel = item.relative_to(run_path)
            typer.echo(f"  {rel}  ({_format_size(item.stat().st_size)})")


def _resolve_run_id(store: LocalRunStore, run_id: str) -> str:
    """Resolve a run ID prefix to a full run ID."""
    all_runs = store.list_runs()
    matches = [r for r in all_runs if r.startswith(run_id)]
    if not matches:
        typer.echo(f"No run found matching '{run_id}'")
        raise typer.Exit(code=1)
    if len(matches) > 1:
        typer.echo(f"Ambiguous run ID '{run_id}', matches: {', '.join(matches[:5])}")
        raise typer.Exit(code=1)
    return matches[0]


@app.command("export")
def export_run(
    run_id: str = typer.Argument(help="Run UUID (full or prefix)."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    output_dir: Path = typer.Option(
        Path("./exports"),
        "--output-dir",
        "-o",
        help="Directory to write the export archive to.",
    ),
    s3_bucket: str = typer.Option(
        None,
        "--s3-bucket",
        help="S3 bucket for remote export.",
    ),
    s3_prefix: str = typer.Option(
        "runs/",
        "--s3-prefix",
        help="S3 key prefix for remote export.",
    ),
) -> None:
    """Export a run as a tar.gz archive, optionally to S3."""
    store = _get_store(project_dir)
    resolved_id = _resolve_run_id(store, run_id)

    from aptl.core.exporter import export_local, export_s3

    if s3_bucket:
        try:
            uri = export_s3(store, resolved_id, s3_bucket, s3_prefix, output_dir)
            typer.echo(f"Exported to S3: {uri}")
        except ImportError as e:
            typer.echo(f"Error: {e}")
            raise typer.Exit(code=1)
    else:
        archive = export_local(store, resolved_id, output_dir)
        typer.echo(f"Exported to: {archive}")


@app.command("export-bundle")
def export_bundle(
    run_id: str = typer.Argument(help="Run UUID (full or prefix)."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    output_dir: Path = typer.Option(
        Path("./exports"),
        "--output-dir",
        "-o",
        help="Directory to write the bundle to (must be outside the run tree).",
    ),
    projection: list[str] = typer.Option(
        None,
        "--projection",
        "-p",
        help="Derived projection(s) to include: jsonl, parquet, ocsf. Repeatable.",
    ),
    verify: bool = typer.Option(
        True,
        "--verify/--no-verify",
        help="Self-verify the bundle after building.",
    ),
) -> None:
    """Export a run as a portable, self-describing evidence bundle (local/offline).

    Packages the run's verified artifact closure with a machine-readable
    inventory/data-dictionary, the published RAES schemas, and any requested
    loss-accounted projections, into a deterministic archive a third party can
    verify without importing APTL internals.
    """
    from aptl.core.evidence_bundle import (
        BundleError,
        BundleOptions,
        build_evidence_bundle,
    )
    from aptl.core.evidence_bundle.projections import available_formats

    store = _get_store(project_dir)
    resolved_id = _resolve_run_id(store, run_id)
    run_dir = store.get_run_path(resolved_id)

    formats = list(projection or [])
    unknown = sorted(set(formats) - available_formats())
    if unknown:
        known = ", ".join(sorted(available_formats()))
        typer.echo(
            f"Unknown projection format(s): {', '.join(unknown)}; known: {known}"
        )
        raise typer.Exit(code=1)

    output_path = output_dir / f"{resolved_id}.evidence-bundle.tar"
    try:
        result = build_evidence_bundle(
            run_dir,
            resolved_id,
            output_path,
            options=BundleOptions(projections=formats, self_verify=verify),
        )
    except BundleError as exc:
        typer.echo(f"Error building bundle: {exc}")
        raise typer.Exit(code=1) from exc

    typer.echo(f"Exported evidence bundle: {result.archive.archive_path}")
    typer.echo(f"  root identity: {result.root_identity}")
    typer.echo(
        f"  members: {result.archive.member_count}  size: {result.archive.size} bytes"
    )
    if result.unsealed:
        typer.echo(
            "  seal: UNSEALED (no #444 verified seal available; "
            "exported with disclosed limitations)"
        )
    if result.limitations:
        typer.echo(f"  limitations: {len(result.limitations)}")
        for limitation in result.limitations:
            subject = f" [{limitation.subject}]" if limitation.subject else ""
            typer.echo(f"    - {limitation.code}: {limitation.detail}{subject}")


@app.command("verify-bundle")
def verify_bundle_command(
    bundle_path: Path = typer.Argument(help="Path to an evidence-bundle .tar archive."),
) -> None:
    """Verify an evidence bundle's integrity, inventory, and root identity."""
    from aptl.core.evidence_bundle import verify_bundle

    report = verify_bundle(bundle_path)
    typer.echo(f"root identity: {report.root_identity}")
    typer.echo(f"members: {report.member_count}  seal: {report.seal_scope}")
    if report.ok:
        typer.echo("OK: bundle verified")
        return
    typer.echo("FAILED:")
    for issue in report.issues:
        typer.echo(f"  - {issue}")
    raise typer.Exit(code=1)
