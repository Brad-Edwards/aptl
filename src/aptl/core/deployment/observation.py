"""Request-scoped evidence retained across deployment and observation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, repr=False)
class CompletedContainerReceipt:
    """Bounded readback captured before verified one-shot container removal."""

    inspect: dict[str, Any] = field(repr=False)
    image_digest: str | None = None
    image_config_id: str | None = None
    files: dict[str, bytes] = field(default_factory=dict, repr=False)


@dataclass
class DeploymentObservationContext:
    """Evidence produced and consumed within one exact backend apply."""

    completed_autoremove: dict[str, CompletedContainerReceipt] = field(
        default_factory=dict,
        repr=False,
    )

    def record_completed_autoremove(
        self,
        name: str,
        receipt: CompletedContainerReceipt,
    ) -> None:
        """Record one receipt after the backend verifies container absence."""

        self.completed_autoremove[name] = CompletedContainerReceipt(
            inspect=deepcopy(receipt.inspect),
            image_digest=receipt.image_digest,
            image_config_id=receipt.image_config_id,
            files=deepcopy(receipt.files),
        )

    def autoremove_verified(self, name: str) -> bool:
        """Return whether this apply verified removal of ``name``."""

        return name in self.completed_autoremove

    def completed_inspect(self, name: str) -> dict[str, Any]:
        """Return an isolated copy of a completed container's daemon state."""

        receipt = self.completed_autoremove.get(name)
        return deepcopy(receipt.inspect) if receipt is not None else {}

    def completed_image_digest(self, name: str) -> str | None:
        """Return a completed container's observed manifest digest."""

        receipt = self.completed_autoremove.get(name)
        return receipt.image_digest if receipt is not None else None

    def completed_image_config_id(self, name: str) -> str | None:
        """Return a completed container's observed image config id."""

        receipt = self.completed_autoremove.get(name)
        return receipt.image_config_id if receipt is not None else None

    def completed_file_read(
        self,
        name: str,
        path: str,
        *,
        max_bytes: int,
    ) -> bytes | None:
        """Return a bounded file captured before verified removal."""

        receipt = self.completed_autoremove.get(name)
        if receipt is None:
            return None
        payload = receipt.files.get(path)
        if payload is None or len(payload) > max_bytes:
            return None
        return payload


__all__ = ["CompletedContainerReceipt", "DeploymentObservationContext"]
