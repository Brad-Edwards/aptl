"""SDL composition and packaging commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aptl.core.sdl.composition import expand_sdl_modules
from aptl.core.sdl.module_registry import (
    LOCKFILE_NAME,
    load_lockfile,
    publish_module_to_oci_layout,
    resolve_lock_records,
    write_lockfile,
)
from aptl.core.sdl.parser import _load_normalized_data, parse_sdl_file

app = typer.Typer(help="SDL composition and packaging.")


@app.command("resolve")
def resolve(
    path: Path = typer.Argument(..., exists=True, readable=True),
    lockfile: Path | None = typer.Option(
        None,
        "--lockfile",
        help=f"Override lockfile path (default: alongside SDL as {LOCKFILE_NAME}).",
    ),
) -> None:
    """Resolve SDL imports and write/update the lockfile."""
    resolved = resolve_lock_records(path)
    output_path = lockfile or (path.parent / LOCKFILE_NAME)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(resolved.model_dump(mode="python"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    typer.echo(str(output_path))


@app.command("verify-imports")
def verify_imports(
    path: Path = typer.Argument(..., exists=True, readable=True),
) -> None:
    """Verify lockfile, trust policy, and import expansion."""
    existing = load_lockfile(path.parent)
    if existing is None:
        raise typer.BadParameter(
            f"No {LOCKFILE_NAME} found next to {path}; run `aptl sdl resolve` first."
        )
    expected = resolve_lock_records(path)
    if expected.model_dump(mode="python") != existing.model_dump(mode="python"):
        raise typer.BadParameter(
            "Import lockfile is stale or does not match current resolution."
        )
    parse_sdl_file(path)
    typer.echo("imports verified")


@app.command("publish")
def publish(
    path: Path = typer.Argument(..., exists=True, readable=True),
    output_dir: Path = typer.Option(
        Path("dist"),
        "--output-dir",
        help="Directory where the OCI layout will be written.",
    ),
    signer_id: str = typer.Option("", "--signer-id", help="Signer identity label."),
    private_key: Path | None = typer.Option(
        None,
        "--private-key",
        exists=True,
        readable=True,
        help="Optional Ed25519 PEM private key used to sign the module bundle.",
    ),
) -> None:
    """Package an SDL module as an OCI image layout."""
    result = publish_module_to_oci_layout(
        path,
        output_dir=output_dir,
        signer_id=signer_id,
        private_key_path=private_key,
    )
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
