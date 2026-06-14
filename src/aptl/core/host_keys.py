"""Server SSH host-key trust material for the terminal relay (ADR-040).

This module owns *server* identity for the operator-facing WebSocket
terminal relay, a contract kept deliberately separate from the operator
client key (``aptl.core.ssh``) and target ``authorized_keys`` (the
``./keys`` bind mount). It captures each lab SSH endpoint's host key at
lab start — trust-on-first-use is permitted only here, inside
provisioning, on the trusted host — and writes a ``known_hosts`` file
under the ignored ``.aptl/`` generated-state root (ADR-028). The terminal
relay loads that file and verifies every connection against it, failing
closed on a missing pin or a host-key mismatch (issue #418).

Public ``known_hosts`` lines are not secrets, but they are generated
runtime state rather than checked-in config, so they live under
``.aptl/`` with the same containment, atomic-write, and permission
discipline the credential renderer uses.
"""

import asyncio
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from aptl.core.snapshot import SSHEndpoint
from aptl.utils.logging import get_logger

log = get_logger("host_keys")

# Generated, gitignored runtime state (``.aptl/`` is the ADR-028 state
# root). The relay derives the same path from the project dir, so the two
# stay in sync without a second constant.
KNOWN_HOSTS_RELPATH = Path(".aptl/known_hosts")

# Owner-only directory is the real host-side access control; the file
# itself is world-readable (0o644) — the pins are public host keys, and
# the 0o700 parent already keeps other local users out.
_DIR_MODE = 0o700
_FILE_MODE = 0o644

# Bounds a single host-key capture so an unreachable or wedged endpoint
# cannot stall lab start.
_CAPTURE_TIMEOUT_SECONDS = 10


class HostKeyError(ValueError):
    """Raised when host-key trust material cannot be written safely."""


@dataclass
class HostKeyPinResult(object):
    """Outcome of a :func:`pin_terminal_host_keys` run."""

    path: Path
    pinned: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


def known_hosts_path(project_dir: Path) -> Path:
    """Return the canonical ``.aptl/known_hosts`` path under *project_dir*.

    The project root is resolved (symlinks followed) before the fixed
    relative path is joined, and the result is asserted to lie under that
    resolved root, so the returned path is always provably rooted at the
    real project directory.
    """
    root = project_dir.resolve()
    candidate = root / KNOWN_HOSTS_RELPATH
    if not candidate.is_relative_to(root):
        raise HostKeyError(
            f"known_hosts path {candidate} escapes project root {root}"
        )
    return candidate


def format_known_hosts_line(host: str, port: int, key: "asyncssh.SSHKey") -> str:
    """Render one OpenSSH ``known_hosts`` line for *host*:*port*.

    Standard port 22 uses a plain ``host`` field; any other port uses the
    bracketed ``[host]:port`` form. The host field MUST match the exact
    ``asyncssh.connect(host=..., port=...)`` value the relay later dials —
    bridge IPs and ``localhost`` pins are not interchangeable (ADR-040).
    """
    exported = key.export_public_key("openssh").decode().split()
    # Keep only "<keytype> <base64>"; drop any trailing comment.
    key_fields = " ".join(exported[:2])
    host_field = host if port == 22 else f"[{host}]:{port}"
    return f"{host_field} {key_fields}"


async def _capture_host_key(
    endpoint: SSHEndpoint, key_path: Path
) -> "asyncssh.SSHKey":
    """Connect once and return the server's presented host key.

    ``known_hosts=None`` is used *only here*, inside lab-start
    provisioning on the trusted host — the permitted trust-on-first-use
    capture (ADR-040). The captured key becomes the pin the operator
    session later verifies against.
    """
    async with asyncssh.connect(
        host=endpoint.host,
        port=endpoint.port,
        username=endpoint.user,
        client_keys=[str(key_path)],
        known_hosts=None,
    ) as conn:
        return conn.get_server_host_key()


def pin_terminal_host_keys(
    project_dir: Path,
    endpoints: list[SSHEndpoint],
    key_path: Path,
) -> HostKeyPinResult:
    """Capture and persist host-key pins for every reachable *endpoint*.

    Each endpoint is probed independently; a probe that fails (endpoint
    not yet reachable, auth issue, timeout) is logged and skipped rather
    than aborting lab start. An unpinned endpoint simply makes the relay
    fail closed for that container until the next ``aptl lab start``. The
    ``known_hosts`` file is always (re)written atomically with whatever
    pins succeeded — including an empty file when nothing was reachable,
    so the relay sees a present-but-unmatched file rather than a missing
    one.
    """
    lines: list[str] = []
    pinned: list[str] = []
    failed: list[str] = []
    for endpoint in endpoints:
        try:
            key = asyncio.run(
                asyncio.wait_for(
                    _capture_host_key(endpoint, key_path),
                    timeout=_CAPTURE_TIMEOUT_SECONDS,
                )
            )
        # Per-endpoint probe failures are non-fatal: log and skip so one
        # unreachable endpoint cannot abort the whole pinning run.
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Could not pin SSH host key for %s (%s:%d): %s",
                endpoint.name,
                endpoint.host,
                endpoint.port,
                exc,
            )
            failed.append(endpoint.name)
            continue
        lines.append(format_known_hosts_line(endpoint.host, endpoint.port, key))
        pinned.append(endpoint.name)

    target = _write_known_hosts(project_dir, lines)
    log.info(
        "Pinned %d/%d terminal SSH host keys to %s",
        len(pinned),
        len(endpoints),
        target,
    )
    return HostKeyPinResult(path=target, pinned=pinned, failed=failed)


def _write_known_hosts(project_dir: Path, lines: list[str]) -> Path:
    """Write the pin lines to ``.aptl/known_hosts`` atomically.

    The ``.aptl/`` parent is created owner-only and its resolved path is
    checked against the literal expected location so a symlinked chain
    cannot redirect the write outside the project root (ADR-028).
    """
    target = known_hosts_path(project_dir)
    parent = target.parent
    expected_parent = project_dir.resolve() / KNOWN_HOSTS_RELPATH.parent

    # Containment BEFORE any filesystem mutation (ADR-028/ADR-040): if the
    # ``.aptl`` state dir already exists, reject a symlink — or any path
    # whose resolved location is not the literal expected directory —
    # before mkdir/chmod/write. ``Path.chmod`` follows symlinks, so a
    # pre-existing ``.aptl`` symlink would otherwise mutate an out-of-tree
    # path before the guard could fire.
    if parent.is_symlink() or (
        parent.exists() and parent.resolve() != expected_parent
    ):
        raise HostKeyError(
            f"known_hosts parent {parent} resolves to {parent.resolve()}, "
            f"not {expected_parent}; refusing to write through a symlink."
        )

    parent.mkdir(parents=True, exist_ok=True)
    # Re-check after creation: parents=True could materialize the dir
    # through a symlinked ancestor that did not exist above.
    if parent.resolve() != expected_parent:
        raise HostKeyError(
            f"known_hosts parent {parent} resolves to {parent.resolve()}, "
            f"not {expected_parent}; refusing to write through a symlink."
        )
    _enforce_mode(parent, _DIR_MODE, "directory")

    content = "".join(f"{line}\n" for line in lines)
    _atomic_write(target, content)
    return target


def _enforce_mode(path: Path, mode: int, kind: str) -> None:
    """``chmod`` *path* to *mode* and, on POSIX, verify it stuck."""
    try:
        path.chmod(mode)
    except (OSError, NotImplementedError) as exc:
        if os.name == "posix":
            raise HostKeyError(
                f"Could not set mode {oct(mode)} on known_hosts {kind} "
                f"{path}: {exc}"
            ) from exc
        return  # pragma: no cover
    if os.name != "posix":  # pragma: no cover
        return
    effective = path.stat().st_mode & 0o777
    if effective != mode:
        raise HostKeyError(
            f"known_hosts {kind} {path} retained mode {oct(effective)}, "
            f"required {oct(mode)}"
        )


def _atomic_write(target: Path, content: str) -> None:
    """Write *content* to *target* via a temp file + ``os.replace``."""
    parent = target.parent
    fd, tmp_name = tempfile.mkstemp(
        dir=parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _enforce_mode(target, _FILE_MODE, "file")
