"""Create one disposable qcow2 overlay over a cached seat image.

The seat image is shared, read-only and content-addressed, so it lives in the
user's image cache rather than inside any one seat root.  Each seat gets its
own overlay over it; destroying the overlay destroys that seat's credentials,
Docker state and run evidence while the image itself is never opened for
writing.

The image's bytes were verified when it was downloaded, so this does not
re-hash a multi-gigabyte file on the way to booting it.  What it does check is
what qemu would otherwise take on trust: that the base really is a standalone
qcow2 with no external backing or data-file dependency, and that it is
read-only on disk.
"""

from __future__ import annotations

import json
import secrets
import subprocess
from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError

_QEMU_TIMEOUT_SECONDS = 120
_MAX_METADATA_BYTES = 1024 * 1024

# A backing or data-file reference would make the overlay depend on something
# outside the verified image, so any of these disqualifies a base image.
_EXTERNAL_FIELDS = (
    "backing-filename",
    "backing_filename",
    "full-backing-filename",
    "data-file",
)


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one bounded qemu-img invocation for the overlay."""

    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=True,
            timeout=_QEMU_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SeatLauncherError(
            "corrupt-overlay", f"{argv[0]} could not be run for the seat overlay"
        ) from exc


def require_standalone_image(image: Path) -> None:
    """Refuse a base image that is not a self-contained read-only qcow2."""

    try:
        status = image.stat(follow_symlinks=False)
    except OSError as exc:
        raise SeatLauncherError("corrupt-overlay", "seat image is unreadable") from exc
    if status.st_mode & 0o222:
        raise SeatLauncherError("corrupt-overlay", "seat image must be read-only")

    result = _run(["qemu-img", "info", "--output=json", str(image)])
    if len(result.stdout) > _MAX_METADATA_BYTES:
        raise SeatLauncherError(
            "corrupt-overlay", "seat image metadata exceeds the admission limit"
        )
    try:
        document = json.loads(result.stdout)
    except ValueError as exc:
        raise SeatLauncherError(
            "corrupt-overlay", "seat image metadata is invalid"
        ) from exc
    if not isinstance(document, dict) or document.get("format") != "qcow2":
        raise SeatLauncherError("corrupt-overlay", "seat image must be qcow2")
    if any(document.get(field) for field in _EXTERNAL_FIELDS):
        raise SeatLauncherError(
            "corrupt-overlay", "seat image must not depend on an external file"
        )


def create_seat_overlay(overlay_path: Path, *, image_path: Path) -> Path:
    """Create the disposable overlay backed by one cached seat image."""

    if overlay_path.exists() or overlay_path.is_symlink():
        raise SeatLauncherError("corrupt-overlay", "seat overlay already exists")
    require_standalone_image(image_path)
    overlay_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate = overlay_path.with_name(
        f"{overlay_path.name}.candidate-{secrets.token_hex(8)}"
    )
    try:
        _run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(image_path),
                str(candidate),
            ]
        )
        candidate.chmod(0o600)
        candidate.replace(overlay_path)
    except SeatLauncherError:
        candidate.unlink(missing_ok=True)
        raise
    except OSError as exc:
        candidate.unlink(missing_ok=True)
        raise SeatLauncherError(
            "corrupt-overlay", "seat overlay could not be published"
        ) from exc
    return overlay_path
