"""Atomic, idempotent writer for the generated Suricata rule file."""

from __future__ import annotations

import os
from pathlib import Path


class RuleFileWriter:
    """Write rule content atomically; do nothing if content is unchanged.

    Atomicity comes from writing to ``<target>.tmp`` and renaming. Idempotency
    comes from comparing the would-be content against any existing file before
    touching disk. If the caller passes a non-string the writer raises and the
    existing file stays intact.
    """

    def __init__(self, target: Path) -> None:
        self._target = target

    def write_if_changed(self, content: str) -> bool:
        if not isinstance(content, str):
            raise TypeError("content must be str")

        try:
            existing = self._target.read_text()
        except FileNotFoundError:
            existing = None

        if existing == content:
            return False

        self._target.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._target.with_suffix(self._target.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(self._target)
        return True
