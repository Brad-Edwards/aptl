"""CLI commands for experiment run management."""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aptl.core.config import AptlConfig, RunStorageConfig, find_config, load_config
from aptl.core.runstore import LocalRunStore
from aptl.utils.logging import get_logger

log = get_logger("cli.runs")

_HELP_PROJECT_DIR = "Path to the APTL project directory."
_HELP_RUN_ID = "Run UUID (full or prefix)."

app = typer.Typer(help="Experiment run management.")
console = Console()


def _get_store(project_dir: Path) -> LocalRunStore:
    """Initialize a LocalRunStore from project config."""
    config_path = find_config(project_dir)
    if config_path:
        config = load_config(config_path)
    else:
        config = AptlConfig()

    local_path = Path(config.run_storage.local_path)
    if not local_path.is_absolute():
        local_path = project_dir / local_path

    return LocalRunStore(local_path)


@app.command("list")
def list_runs(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help=_HELP_PROJECT_DIR,
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
        table = Table(title="Experiment Runs")
        table.add_column("Run ID", style="cyan", no_wrap=True)
        table.add_column("Scenario")
        table.add_column("Started")
        table.add_column("Duration")
        table.add_column("Flags")

        for run_id in run_ids:
            try:
                manifest = store.get_run_manifest(run_id)
                duration = manifest.get("duration_seconds", 0)
                minutes = int(duration // 60)
                seconds = int(duration % 60)
                table.add_row(
                    run_id[:12] + "...",
                    manifest.get("scenario_name", "?"),
                    manifest.get("started_at", "?")[:19],
                    f"{minutes}m {seconds}s",
                    str(manifest.get("flags_captured", 0)),
                )
            except (FileNotFoundError, KeyError) as e:
                log.warning("Skipping run %s: %s", run_id, e)
                table.add_row(run_id[:12] + "...", "[red]ERROR[/red]", "", "", "")

        console.print(table)
    else:
        for run_id in run_ids:
            try:
                manifest = store.get_run_manifest(run_id)
                typer.echo(
                    f"{run_id}\t{manifest.get('scenario_name', '?')}\t"
                    f"{manifest.get('started_at', '?')[:19]}"
                )
            except (FileNotFoundError, KeyError):
                typer.echo(f"{run_id}\tERROR")

    typer.echo(f"\n{len(run_ids)} run(s) shown (of {len(store.list_runs())} total)")


def _format_size(size: int) -> str:
    """Format a file size as a human-readable string."""
    if size > 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} MB"
    if size > 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _print_run_files(run_path: Path) -> None:
    """Print the file listing for a run directory."""
    typer.echo("")
    typer.echo("Files:")
    for item in sorted(run_path.rglob("*")):
        if item.is_file():
            rel = item.relative_to(run_path)
            typer.echo(f"  {rel}  ({_format_size(item.stat().st_size)})")


@app.command("show")
def show_run(
    run_id: str = typer.Argument(help=_HELP_RUN_ID),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help=_HELP_PROJECT_DIR,
    ),
) -> None:
    """Show details of a specific run."""
    store = _get_store(project_dir)

    # Support prefix matching
    all_runs = store.list_runs()
    matches = [r for r in all_runs if r.startswith(run_id)]
    if not matches:
        typer.echo(f"No run found matching '{run_id}'")
        raise typer.Exit(code=1)
    if len(matches) > 1:
        typer.echo(f"Ambiguous run ID '{run_id}', matches: {', '.join(matches[:5])}")
        raise typer.Exit(code=1)

    resolved_id = matches[0]

    try:
        manifest = store.get_run_manifest(resolved_id)
    except FileNotFoundError:
        typer.echo(f"Run {resolved_id} has no manifest.")
        raise typer.Exit(code=1)

    duration = manifest.get("duration_seconds", 0)
    minutes = int(duration // 60)
    seconds = int(duration % 60)

    typer.echo(f"Run: {resolved_id}")
    typer.echo(f"  Scenario:     {manifest.get('scenario_name', '?')}")
    typer.echo(f"  Scenario ID:  {manifest.get('scenario_id', '?')}")
    typer.echo(f"  Started:      {manifest.get('started_at', '?')}")
    typer.echo(f"  Finished:     {manifest.get('finished_at', '?')}")
    typer.echo(f"  Duration:     {minutes}m {seconds}s")
    typer.echo(f"  Flags:        {manifest.get('flags_captured', 0)}")

    containers = manifest.get("containers", [])
    if containers:
        typer.echo(f"  Containers:   {', '.join(containers)}")

    # List files in run directory
    run_path = store.get_run_path(resolved_id)
    if run_path.exists():
        _print_run_files(run_path)


@app.command("path")
def run_path(
    run_id: str = typer.Argument(help=_HELP_RUN_ID),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help=_HELP_PROJECT_DIR,
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
    run_id: str = typer.Argument(help=_HELP_RUN_ID),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help=_HELP_PROJECT_DIR,
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
