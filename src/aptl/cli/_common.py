"""Shared CLI plumbing.

Helpers used by multiple subcommand modules — typically the
``find_config`` + ``load_config`` + ``typer.Exit`` boilerplate that every
``aptl <subcommand>`` runs at the start.

Keep this module thin: only put helpers here that are genuinely shared
across CLI surfaces. Subcommand-specific logic stays in the respective
``aptl/cli/<command>.py``.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import NoReturn

import typer

from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.runstore import LocalRunStore
from aptl.utils.redaction import redact


_NO_CONFIG_TEMPLATE = "no aptl.json found in {project_dir}"

# The exit status `aptl doctor` and the lab lifecycle commands share (#1218):
# 0 when the command did what it reports, 1 when it could not, 2 for invalid
# usage. Click already exits with 2 for an unknown option or a bad value.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
# Shape version of every `--json` result. A new field keeps it; removing or
# retyping a field raises it.
JSON_SCHEMA_VERSION = 1


def emit_json_result(command: str, ok: bool, fields: Mapping[str, object]) -> None:
    """Print one JSON result object for ``command`` on standard output.

    ``ok`` is true exactly when the command exits with status 0, so a script
    can read either one.
    """

    payload = {
        "command": command,
        "schema_version": JSON_SCHEMA_VERSION,
        "ok": ok,
        **fields,
    }
    typer.echo(json.dumps(payload, indent=2))


def redact_text(text: str | None) -> str:
    """Return free-form ``text`` for a JSON result with secrets redacted (ADR-012).

    Only the free-form strings go through it. Redacting the whole payload would
    also hide fields whose key looks sensitive, such as the doctor count
    ``pass``.
    """

    return str(redact(text)) if text else ""


def exit_status(ok: bool) -> typer.Exit:
    """Return the exit that reports ``ok`` under the shared contract."""

    return typer.Exit(code=EXIT_OK if ok else EXIT_FAILED)


def refuse_json_prompt(option: str) -> NoReturn:
    """Stop before a destructive action that JSON output cannot confirm."""

    typer.echo(
        f"error: --json with {option} needs --yes, because JSON output cannot "
        "prompt for confirmation",
        err=True,
    )
    raise typer.Exit(code=EXIT_USAGE)


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


def resolve_run_store(
    project_dir: Path,
    config: AptlConfig | None = None,
) -> LocalRunStore:
    """Build a :class:`LocalRunStore` rooted at the project's runs path.

    Single shared helper for every CLI command that needs the run
    archive (``aptl runs *``, ``aptl lab continuity-audit``). When
    ``config`` is provided the caller has already loaded it; otherwise
    we discover it via :func:`find_config` (defaulting to an
    ``AptlConfig()`` if no aptl.json is present, so help-only paths
    don't error out).
    """
    if config is None:
        config_path = find_config(project_dir)
        config = load_config(config_path) if config_path else AptlConfig()

    local_path = Path(config.run_storage.local_path)
    if not local_path.is_absolute():
        local_path = project_dir / local_path
    return LocalRunStore(local_path)


def resolve_optional_config_for_cli(project_dir: Path) -> AptlConfig:
    """Load ``aptl.json`` when present, otherwise return strict defaults.

    Experiment admission has a valid config-free mode, but an existing config
    must still be validated and passed to both persistence and binding
    admission. Error text is intentionally fixed so Pydantic input values
    cannot reach the CLI.
    """

    config_path = find_config(project_dir)
    if config_path is None:
        return AptlConfig()
    try:
        return load_config(config_path)
    except (OSError, ValueError) as exc:
        typer.echo("invalid aptl configuration", err=True)
        raise typer.Exit(code=1) from exc
