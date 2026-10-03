"""Per-user network boundary for a prompt-free seat desktop gateway."""

from __future__ import annotations

import os
from pathlib import Path

from aptl.core.appliance_boundary_inventory import BoundaryEndpoint


def private_desktop(mappings: tuple[BoundaryEndpoint, ...]) -> bool:
    """Only the new, single-publication desktop uses a private host network."""

    return (
        len(mappings) == 1
        and mappings[0].audience == "participant"
        and mappings[0].guest_port == 8080
        and mappings[0].protocol == "tcp"
    )


def in_private_network(pid: int) -> bool:
    """Whether the tracked VM has a different network namespace from caller."""

    try:
        return (
            Path(f"/proc/{pid}/ns/net").stat().st_ino
            != Path("/proc/self/ns/net").stat().st_ino
        )
    except OSError:
        return False


def enter_private_network(pid: int) -> tuple[str, ...]:
    """Enter the tracked user's namespace without a password or shared URL token.

    Linux permits entry to this rootless namespace only from the creator's
    mapped host uid. A different local account cannot open its user namespace.
    """

    if pid <= 0 or not in_private_network(pid):
        raise ValueError("seat desktop network namespace is unavailable")
    if Path(f"/proc/{pid}").stat().st_uid != os.getuid():
        raise ValueError("seat desktop belongs to another host account")
    return (
        "nsenter", "--target", str(pid), "--user", "--net",
        "--preserve-credentials", "--",
    )
