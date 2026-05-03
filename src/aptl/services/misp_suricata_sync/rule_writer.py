"""Atomic, idempotent writer for the generated Suricata rule file."""

from __future__ import annotations

import os
from pathlib import Path


def write_if_changed(target: Path, content: str) -> bool:
    """Write *content* to *target* atomically; no-op if already current.

    Atomicity: write to ``<target>.tmp`` then rename. Idempotency:
    compare the would-be content against any existing file before
    touching disk so the same content twice is two reads and zero
    writes (the loop relies on this to avoid spurious Suricata
    reloads).

    Returns ``True`` when the file was rewritten, ``False`` when the
    content already matched. Raises ``TypeError`` if *content* is not a
    string — the existing file is left intact in that case.
    """
    if not isinstance(content, str):
        raise TypeError("content must be str")

    try:
        existing: str | None = target.read_text()
    except FileNotFoundError:
        existing = None

    if existing == content:
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(target)
    return True
