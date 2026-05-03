"""Shared CLI plumbing.

Helpers used by multiple subcommand modules — typically the
``find_config`` + ``load_config`` + ``typer.Exit`` boilerplate that every
``aptl <subcommand>`` runs at the start.

Keep this module thin: only put helpers here that are genuinely shared
across CLI surfaces. Subcommand-specific logic stays in the respective
``aptl/cli/<command>.py``.
"""

from pathlib import Path
from typing import Optional

import typer

from aptl.core.config import AptlConfig, find_config, load_config


_NO_CONFIG_TEMPLATE = "no aptl.json found in {project_dir}"


def resolve_config_for_cli(
    project_dir: Path,
) -> tuple[AptlConfig, Path]:
    """Locate ``aptl.json`` under ``project_dir``, load and validate it.

    Returns the resolved ``AptlConfig`` and the directory that owns the
    config file (``config_path.parent``) so callers can construct
    deployment backends with the correct ``project_dir`` even when
    config discovery walks up the filesystem.

    Raises ``typer.Exit(1)`` with a stderr message on missing file,
    invalid JSON, or Pydantic validation error.
    """
    config_path = find_config(project_dir)
    if config_path is None:
        typer.echo(
            _NO_CONFIG_TEMPLATE.format(project_dir=project_dir),
            err=True,
        )
        raise typer.Exit(code=1)
    try:
        config = load_config(config_path)
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    return config, config_path.parent


def find_config_for_cli(project_dir: Path) -> Optional[Path]:
    """Find ``aptl.json`` without exiting on absence.

    Some CLI commands (``lab status`` text mode) want to keep working
    when no config file exists. They can use this helper for discovery
    and decide locally what to do with ``None``.
    """
    return find_config(project_dir)
