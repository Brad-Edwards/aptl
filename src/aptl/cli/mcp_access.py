"""Host client setup and the restricted guest transport entry point."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer

from aptl.workbench.profiles import WorkbenchConfigurationError

app = typer.Typer(help="Configure seat-scoped host MCP access.")
OptionPath = Annotated[Path, typer.Option()]
OptionText = Annotated[str, typer.Option()]


@app.command()
def configure(
    access_record: OptionPath,
    grant: OptionPath,
    host_public_key: OptionPath,
    expected_host_key: OptionText,
    identity_file: OptionPath,
    username: OptionText,
    owner_id: OptionText,
    seat_id: OptionText,
    instance_id: OptionText,
    project_dir: OptionPath,
    client: OptionText,
) -> None:
    """Publish project MCP entries using an independently verified SSH host pin."""
    from aptl.core._soc_ca_io import _atomic_write
    from aptl.workbench.access import (
        CallerGrant,
        SeatAccessRecord,
        require_current_access,
    )
    from aptl.workbench.access_clients import client_entries
    from aptl.workbench.client_files import (
        _private_directory,
        _read,
        publish_client_config,
    )
    from aptl.workbench.dispatch import key_fingerprint, normalize_public_key

    try:
        record = SeatAccessRecord.model_validate_json(access_record.read_bytes())
        caller = CallerGrant.model_validate_json(grant.read_bytes())
        require_current_access(record, owner_id=owner_id, seat_id=seat_id)
        public_key = normalize_public_key(host_public_key.read_text())
        if (
            record.instance_id != instance_id
            or key_fingerprint(public_key) != expected_host_key
            or record.host_key_fingerprint != expected_host_key
        ):
            raise WorkbenchConfigurationError(
                "seat transport identity does not match the trusted pin"
            )
        root = project_dir.resolve(strict=True)
        _private_directory(root, ".aptl")
        # Immutable per-generation pins prevent a failed/stale update from changing
        # the trust of a previously published client configuration.
        known = (
            root
            / ".aptl"
            / f"{seat_id}-{record.generation}-{expected_host_key[7:19].replace('/', '_')}.known_hosts"
        )
        endpoint = record.outer_endpoint
        content = f"[{endpoint.address}]:{endpoint.port} {public_key}\n".encode()
        ssh = shutil.which("ssh")
        if ssh is None:
            raise WorkbenchConfigurationError("OpenSSH client is required")
        entries = client_entries(
            record,
            caller,
            ssh_executable=Path(ssh),
            identity_file=identity_file,
            known_hosts=known,
            username=username,
        )
        existing = _read(root, known.relative_to(root).as_posix())
        if existing is not None and existing.encode() != content:
            raise WorkbenchConfigurationError("existing transport pin conflicts")
        _atomic_write(known, content, mode=0o600)
        path = publish_client_config(root, client, record, entries)
    except (ValueError, OSError) as exc:
        typer.echo(f"MCP configuration rejected: {exc}", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"Configured {client}: {path}")


async def _stdio_dispatch(
    binding: Path, grant_id: str, fingerprint: str, selector
) -> None:
    from aptl.workbench.guest_binding import GuestAdmission
    from aptl.workbench.relay import relay_mcp

    with GuestAdmission(binding, grant_id, fingerprint, selector) as admission:
        argv, cwd, env = admission.launch()
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=1024 * 1024)
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer
        )
        transport, protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer
        )
        writer = asyncio.StreamWriter(transport, protocol, None, loop)
        try:
            await relay_mcp(
                reader,
                writer,
                argv=argv,
                cwd=cwd,
                env=env,
                server=admission.server,
                authorize=admission.authorize,
                cleanup_observer=admission.cleanup,
                check_revocation=admission.check_revocation,
            )
        finally:
            writer.close()


@app.command(hidden=True)
def dispatch(
    binding: OptionPath, grant_id: OptionText, key_fingerprint: OptionText
) -> None:
    """Forced-command target; operator-owned key policy supplies every option."""
    from aptl.workbench.dispatch import DispatchSelector

    try:
        selector = DispatchSelector.parse(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
        asyncio.run(_stdio_dispatch(binding, grant_id, key_fingerprint, selector))
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        # Never include binding contents, backend errors, or service credentials.
        typer.echo("MCP transport request rejected", err=True)
        raise typer.Exit(2) from None


@app.command("prepare-guest")
def prepare_guest(request: OptionPath, output_dir: OptionPath) -> None:
    """Enroll host public keys and emit a dedicated restricted listener policy."""
    from aptl.workbench.preparation import TransportPreparation, prepare_guest_transport

    try:
        configuration = TransportPreparation.model_validate_json(request.read_bytes())
        prepare_guest_transport(configuration, output_dir)
    except (ValueError, OSError, KeyError, RuntimeError):
        typer.echo("Guest transport preparation rejected", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"Guest transport prepared: {output_dir}")


@app.command()
def refresh(binding: OptionPath, output: OptionPath) -> None:
    """Refresh a secret-free access record after live deployment checks."""
    from aptl.workbench.preparation import refresh_access

    try:
        refresh_access(binding, output)
    except (ValueError, OSError, RuntimeError):
        typer.echo("Access refresh rejected", err=True)
        raise typer.Exit(2) from None


@app.command()
def revoke(binding: OptionPath, grant_id: OptionText) -> None:
    """Revoke an enrolled caller, including its active MCP connections."""
    from aptl.workbench.preparation import revoke_grant

    try:
        revoke_grant(binding, grant_id)
    except (ValueError, OSError):
        typer.echo("Grant revocation rejected", err=True)
        raise typer.Exit(2) from None
