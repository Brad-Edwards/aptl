"""Safe opening for named virtio serial character-device channels."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def open_character_device(path: Path, flags: int) -> int:
    """Open a device after resolving its kernel-created stable-name symlink.

    Linux exposes named virtio ports below ``/dev/virtio-ports`` as symlinks to
    ``/dev/vport*``. Resolve that stable name first, then retain ``O_NOFOLLOW``
    on the resolved leaf and verify the opened object by descriptor.
    """

    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OSError("guest channel device cannot be resolved") from exc
    open_flags = flags | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, open_flags)
    try:
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
            raise OSError("guest channel endpoint is not a character device")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def write_character_device(path: Path, payload: bytes) -> None:
    """Write the complete payload even when the device accepts short writes."""

    descriptor = open_character_device(path, os.O_WRONLY)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("guest channel device accepted no data")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)
