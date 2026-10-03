"""Host-admin maintenance for a stopped disposable seat overlay."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.locking import seat_mutation_lock
from aptl.appliance.seat.paths import contained_path
from aptl.appliance.seat.persistence import load_seat_record
from aptl.appliance.seat.vm import read_vm_pid


def _stopped_overlay(seat_root: Path) -> tuple[Path, int]:
    """Return the contained overlay and owner after stopped-state checks."""

    record = load_seat_record(seat_root)
    if record is None:
        raise SeatLauncherError("corrupt-seat-state", "seat is not staged")
    if read_vm_pid(seat_root) is not None:
        raise SeatLauncherError("seat-running", "stop the seat before rescue")
    overlay = contained_path(seat_root, record.overlay_path, label="seat overlay")
    info = overlay.stat(follow_symlinks=False)
    owner = seat_root.stat(follow_symlinks=False).st_uid
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
        raise SeatLauncherError("corrupt-seat-state", "seat overlay is unsafe")
    return overlay, owner


def rescue_seat_overlay(seat_root: Path) -> None:
    """Open an offline guest-root shell without changing participant privileges."""

    import pwd

    if os.geteuid() != 0:
        raise SeatLauncherError("host-admin-required", "seat rescue requires host root")
    if not (seat_root / ".lifecycle.lock").is_file():
        raise SeatLauncherError("corrupt-seat-state", "seat lifecycle lock is missing")
    if shutil.which("runuser") is None or shutil.which("virt-rescue") is None:
        raise SeatLauncherError(
            "missing-rescue-tool", "seat rescue requires runuser and virt-rescue"
        )
    with seat_mutation_lock(seat_root):
        overlay, owner = _stopped_overlay(seat_root)
        try:
            account = pwd.getpwuid(owner)
        except KeyError as exc:
            raise SeatLauncherError("corrupt-seat-state", "seat owner is unavailable") from exc
        environment = {
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LIBGUESTFS_BACKEND": "direct",
        }
        result = subprocess.run(
            ["runuser", "-u", account.pw_name, "--", "virt-rescue", "--rw",
             "--inspector", "--add", str(overlay)],
            check=False, env=environment,
        )
        if result.returncode != 0:
            raise SeatLauncherError("failed-rescue", "seat rescue did not complete")
