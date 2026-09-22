"""Structural contracts for plugin-owned live-gate alert sources."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Protocol


class AlertReadResult(Protocol):
    """The bounded result core needs from a plugin-owned alert reader."""

    records: Sequence[Mapping[str, object]]
    loss_category: str | None

    @property
    def complete(self) -> bool:
        """Return whether the declared source was read without evidence loss."""

        ...


AlertReader = Callable[[object, object, str, str], AlertReadResult]


__all__ = ["AlertReader", "AlertReadResult"]
