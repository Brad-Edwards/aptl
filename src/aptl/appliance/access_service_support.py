"""Filesystem and account preparation for guest access supervision."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.appliance.seat.launch_descriptor import SeatLaunchDescriptor
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.core._soc_ca_io import _atomic_write
from aptl.core.appliance_boundary_inventory import GuestBoundaryObservation
from aptl.core.config import load_config
from aptl.workbench.guest_binding import (
    ApplianceAccessObservation,
    ApplianceAccessPaths,
)
from aptl.workbench.profiles import WorkbenchConfigurationError

if TYPE_CHECKING:
    from aptl.appliance.seat.access import GuestAccessRequest


@dataclass(frozen=True)
class _AccessAccount:
    """POSIX account fields required by the guest access supervisor."""

    pw_uid: int
    pw_gid: int
    pw_dir: str


def _access_account(username: str) -> _AccessAccount:
    """Resolve the guest dispatcher account without breaking portable imports."""

    try:
        import pwd
    except ModuleNotFoundError as exc:
        raise WorkbenchConfigurationError(
            "guest access supervision requires POSIX"
        ) from exc
    try:
        account = pwd.getpwnam(username)
    except KeyError as exc:
        raise WorkbenchConfigurationError(
            "guest access account is unavailable"
        ) from exc
    return _AccessAccount(
        pw_uid=account.pw_uid,
        pw_gid=account.pw_gid,
        pw_dir=account.pw_dir,
    )


def _descriptor_digest(path: Path) -> str:
    """Return the SHA-256 identity of one staged launch descriptor."""

    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _ensure_host_key(path: Path) -> None:
    """Generate one overlay-local host key without replacing an existing key."""

    public = path.with_suffix(path.suffix + ".pub")
    if path.exists() or public.exists():
        if not path.is_file() or not public.is_file():
            raise WorkbenchConfigurationError("guest host key state is incomplete")
        return
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    path.chmod(0o600)
    public.chmod(0o644)


def _write_runtime_observation(
    path: Path,
    request: GuestAccessRequest,
    guest: GuestBoundaryObservation,
    *,
    uid: int,
    gid: int,
) -> None:
    """Persist a private host/guest boundary observation for the dispatcher."""

    observation = ApplianceAccessObservation(
        schema_version="aptl.mcp-boundary-observation/v1",
        observed_at=datetime.now(UTC),
        binding=request.binding,
        host=request.host_observation,
        guest=guest,
    )
    _atomic_write(path, (observation.model_dump_json() + "\n").encode(), mode=0o600)
    os.chown(path, uid, gid)


def _assign_management_state(project: Path, *, uid: int, gid: int) -> None:
    """Give the dedicated dispatcher identity only the generated private state."""

    run_store = Path(load_config(project / "aptl.json").run_storage.local_path)
    if not run_store.is_absolute():
        run_store = project / run_store
    if (
        run_store.resolve() == project.resolve()
        or not run_store.resolve().is_relative_to(project.resolve())
    ):
        raise WorkbenchConfigurationError(
            "guest run store escapes private project state"
        )
    targets = (project / ".aptl", project / ".mcp.json", run_store)
    for target in targets:
        if target.is_symlink() or not target.exists():
            raise WorkbenchConfigurationError("guest management state is unsafe")
        if target.is_dir():
            _assign_management_directory(target, uid=uid, gid=gid)
        else:
            os.chown(target, uid, gid, follow_symlinks=False)


def _assign_management_directory(directory: Path, *, uid: int, gid: int) -> None:
    """Reject links and assign one generated management directory tree."""

    for root, directories, files in os.walk(directory, followlinks=False):
        root_path = Path(root)
        entries = (*directories, *files)
        if any((root_path / name).is_symlink() for name in entries):
            raise WorkbenchConfigurationError(
                "guest management state contains a symbolic link"
            )
        os.chown(root_path, uid, gid, follow_symlinks=False)
        for name in files:
            os.chown(root_path / name, uid, gid, follow_symlinks=False)


def _prepare_dispatch_home(home: Path, *, uid: int, gid: int) -> None:
    """Give the dispatcher the lab-only SSH identity, not supervisor home access."""
    from aptl.utils.pathsafe import read_contained_nofollow

    directory = home / ".ssh"
    target = directory / "aptl_lab_key"
    if home.is_symlink() or directory.is_symlink() or target.is_symlink():
        raise WorkbenchConfigurationError("dispatcher SSH identity path is unsafe")
    payload = read_contained_nofollow(Path.home(), ".ssh/aptl_lab_key")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    _atomic_write(target, payload, mode=0o600)
    os.chown(directory, uid, gid)
    os.chown(target, uid, gid)


def _prepare_dispatch_ca(project: Path, *, gid: int) -> None:
    """Permit group traversal to the public root, leaving key material private."""
    from aptl.core._soc_ca_io import _canonical_output_dir

    directory = _canonical_output_dir(project)
    if directory.is_symlink() or not directory.is_dir():
        raise WorkbenchConfigurationError("guest public CA directory is unsafe")
    os.chown(directory, -1, gid)
    directory.chmod(0o710)


def _stage_dispatch_metadata(
    launch: tuple[SeatLaunchDescriptor, ApplianceBoundaryPolicy],
    paths: ApplianceAccessPaths,
    destination: Path,
    *,
    gid: int,
) -> ApplianceAccessPaths:
    """Project only the verified launch into dispatcher-readable state.

    The launch is two small documents the host wrote and the guest already
    authenticated, so this copies exactly those rather than re-deriving a
    release tree.
    """
    from aptl.utils.pathsafe import read_contained_nofollow

    del launch
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    copies = {
        "launch_descriptor": destination / "appliance-launch.json",
    }
    payloads = {
        destination
        / "boundary-policy.json": read_contained_nofollow(
            paths.launch_descriptor.parent, "boundary-policy.json"
        )
    }
    for field, target in copies.items():
        source = getattr(paths, field)
        payloads[target] = read_contained_nofollow(source.parent, source.name)
    for target, payload in payloads.items():
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_write(target, payload, mode=0o640)
        os.chown(target, -1, gid)
    for directory in (destination, *(p for p in destination.rglob("*") if p.is_dir())):
        directory.chmod(0o750)
        os.chown(directory, -1, gid)
    return paths.model_copy(update=copies)
