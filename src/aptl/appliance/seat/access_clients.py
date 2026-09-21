"""Host client publication for generation-scoped appliance access."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core._soc_ca_io import _atomic_write
from aptl.workbench.preparation import EnrolledKey
from aptl.workbench.profiles import WorkbenchConfigurationError

if TYPE_CHECKING:
    from aptl.appliance.seat.access import GuestAccessBundle, GuestAccessRequest


def configure_host_clients(
    *,
    bundle: GuestAccessBundle,
    project_dir: Path,
    identity_file: Path,
    username: str,
    clients: tuple[str, ...],
) -> tuple[Path, ...]:
    """Publish native Claude/Codex config using the VM-returned host pin."""

    from aptl.workbench.access_clients import client_entries
    from aptl.workbench.client_files import (
        _private_directory,
        _read,
        publish_client_config,
    )
    from aptl.workbench.dispatch import key_fingerprint, normalize_public_key

    if (
        not clients
        or len(set(clients)) != len(clients)
        or any(client not in {"claude", "codex"} for client in clients)
    ):
        raise WorkbenchConfigurationError("select one or more supported MCP clients")
    root = project_dir.resolve(strict=True)
    public_key = normalize_public_key(bundle.host_public_key)
    fingerprint = key_fingerprint(public_key)
    if bundle.access.host_key_fingerprint != fingerprint:
        raise WorkbenchConfigurationError("guest access host pin is inconsistent")
    ssh = shutil.which("ssh")
    if ssh is None:
        raise WorkbenchConfigurationError("OpenSSH client is required")
    _private_directory(root, ".aptl")
    known = (
        root
        / ".aptl"
        / (
            f"{bundle.seat_id}-{bundle.generation}-"
            f"{fingerprint[7:19].replace('/', '_')}.known_hosts"
        )
    )
    endpoint = bundle.access.outer_endpoint
    content = f"[{endpoint.address}]:{endpoint.port} {public_key}\n".encode()
    existing = _read(root, known.relative_to(root).as_posix())
    if existing is not None and existing.encode() != content:
        raise WorkbenchConfigurationError("existing transport pin conflicts")
    _atomic_write(known, content, mode=0o600)
    entries = client_entries(
        bundle.access,
        bundle.grant,
        ssh_executable=Path(ssh),
        identity_file=identity_file,
        known_hosts=known,
        username=username,
    )
    return tuple(
        publish_client_config(root, client, bundle.access, entries)
        for client in clients
    )


def enrolled_key(request: GuestAccessRequest) -> EnrolledKey:
    """Project the public request into the existing restricted transport model."""

    item = request.enrollment
    return EnrolledKey(
        grant_id=item.grant_id,
        public_key=item.public_key,
        profile=item.profile,
        expires_at=item.expires_at,
    )
