#!/usr/bin/env python3
"""Sample aggregate QEMU CPU, resident memory, and overlay allocation peaks."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

import rfc8785


def _pid(root: Path) -> int | None:
    try:
        value = json.loads((root / "vm.pid").read_bytes())["pid"]
        return value if isinstance(value, int) and value > 0 else None
    except (OSError, KeyError, TypeError, ValueError):
        return None


def _process(pid: int) -> tuple[int, int] | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        memory = next(
            int(line.split()[1]) * 1024
            for line in Path(f"/proc/{pid}/status").read_text().splitlines()
            if line.startswith("VmRSS:")
        )
        return ticks, memory
    except (OSError, StopIteration, ValueError, IndexError):
        return None


def _system_ticks() -> int:
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    return sum(int(value) for value in fields)


def _disk(root: Path) -> int:
    try:
        state = json.loads((root / "seat-state.json").read_bytes())
        info = (root / state["overlay_path"]).stat(follow_symlinks=False)
        return info.st_blocks * 512
    except (OSError, KeyError, TypeError, ValueError):
        return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seat-root", type=Path, action="append", required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    peak_cpu = 0.0
    peak_memory = 0
    peak_disk = 0
    previous: tuple[int, int] | None = None
    while not args.stop_file.exists():
        processes = [value for root in args.seat_root if (value := _pid(root))]
        samples = [value for pid in processes if (value := _process(pid))]
        process_ticks = max((item[0] for item in samples), default=0)
        system_ticks = _system_ticks()
        peak_memory = max(peak_memory, *(item[1] for item in samples))
        peak_disk = max(peak_disk, *(_disk(root) for root in args.seat_root))
        if previous is not None and system_ticks > previous[1]:
            peak_cpu = max(
                peak_cpu,
                min(
                    100.0,
                    100.0
                    * max(0, process_ticks - previous[0])
                    / (system_ticks - previous[1]),
                ),
            )
        previous = process_ticks, system_ticks
        time.sleep(0.2)
    payload = rfc8785.dumps(
        {
            "peak_cpu_percent": peak_cpu,
            "peak_memory_bytes": peak_memory,
            "peak_runtime_disk_bytes": peak_disk,
        }
    )
    descriptor = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


if __name__ == "__main__":
    main()
