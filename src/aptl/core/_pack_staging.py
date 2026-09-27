"""Bounded, no-follow acquisition before env-packs validates portable content."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from aptl.utils.pathsafe import open_contained_nofollow, open_dir_contained_nofollow

# Acquisition budgets bound work before a manifest can be trusted. They are
# filesystem limits, not another definition of the upstream pack format.
MAX_MEMBERS = 4096
MAX_BYTES = 1024 * 1024 * 1024
MAX_DEPTH = 64


def copy_pack(source: Path, destination: Path) -> None:  # NOSONAR
    """Copy regular files privately, including legitimate installer hardlinks.

    Walk source components without following links and read each file through
    the same checked handle. Upstream validators then establish exact inventory
    and content identity. Installer bytecode is the sole inventory exclusion.
    """
    absolute = source.absolute()
    anchor = Path(absolute.anchor)
    relative = absolute.relative_to(anchor)
    pending = [Path()]
    members = total = 0
    while pending:
        directory = pending.pop()
        fd = open_dir_contained_nofollow(anchor, relative / directory)
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    members += 1
                    if members > MAX_MEMBERS:  # NOSONAR
                        raise ValueError("source member budget exceeded")
                    item = directory / entry.name
                    mode = entry.stat(follow_symlinks=False).st_mode
                    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):  # NOSONAR
                        raise ValueError("unsafe source member")
                    if entry.name == "__pycache__" or entry.name.endswith(  # NOSONAR
                        (".pyc", ".pyo")
                    ):
                        continue
                    if len(item.parts) > MAX_DEPTH:  # NOSONAR
                        raise ValueError("source depth budget exceeded")
                    if stat.S_ISDIR(mode):  # NOSONAR
                        pending.append(item)
                    else:
                        total += _copy_file(
                            anchor,
                            relative / item,
                            destination / item,
                            MAX_BYTES - total,
                        )
        finally:
            os.close(fd)


def _copy_file(anchor: Path, source: Path, target: Path, remaining: int) -> int:  # NOSONAR
    with open_contained_nofollow(anchor, source) as reader:
        info = os.fstat(reader.fileno())
        if info.st_size > remaining:
            raise ValueError("source byte budget exceeded")
        target.parent.mkdir(parents=True, exist_ok=True)
        copied = 0
        with target.open("xb") as writer:
            while chunk := reader.read(min(1024 * 1024, remaining - copied + 1)):
                copied += len(chunk)
                if copied > remaining:
                    raise ValueError("source byte budget exceeded")
                writer.write(chunk)
        target.chmod(stat.S_IMODE(info.st_mode) & 0o777)
    return copied
