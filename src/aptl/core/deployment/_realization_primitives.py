"""Primitive image, network, and environment realization values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ImageRealizationMode = Literal["pull", "build"]

# An omitted author host address binds loopback, never all interfaces.
LOOPBACK_HOST_IP = "127.0.0.1"
_ENVIRONMENT_VARIABLE_NAME = re.compile(r"[A-Za-z_]\w*", flags=re.ASCII)


def valid_environment_variable_name(value: object) -> bool:
    """Return whether ``value`` is a conventional, env-file-safe name."""

    return bool(
        isinstance(value, str)
        and _ENVIRONMENT_VARIABLE_NAME.fullmatch(value) is not None
    )


@dataclass(frozen=True)
class DeploymentImageRealization:
    """One image operation resolved from scenario-owned source metadata."""

    address: str
    service_name: str
    source_name: str
    source_version: str
    image_ref: str
    mode: ImageRealizationMode
    policy_rule: str
    dockerfile_path: str | None = None
    context_path: str | None = None
    provenance: dict[str, int] | None = None

    def details(self) -> dict[str, object]:
        """Return a serializable image realization projection."""

        details: dict[str, object] = {
            "address": self.address,
            "service_name": self.service_name,
            "source_name": self.source_name,
            "source_version": self.source_version,
            "image_ref": self.image_ref,
            "mode": self.mode,
            "policy_rule": self.policy_rule,
        }
        if self.dockerfile_path is not None:
            details["dockerfile_path"] = self.dockerfile_path
        if self.context_path is not None:
            details["context_path"] = self.context_path
        if self.provenance is not None:
            details["provenance"] = dict(self.provenance)
        return details


@dataclass(frozen=True)
class DeploymentNetworkRealization:
    """One scenario-declared network the backend may materialize."""

    name: str
    cidr: str | None = None
    gateway: str | None = None
    internal: bool | None = None


@dataclass(frozen=True)
class DeploymentNetworkAttachment:
    """One node-to-network attachment requested by the scenario."""

    network: str
    ipv4_address: str | None = None


__all__ = (
    "DeploymentImageRealization",
    "DeploymentNetworkAttachment",
    "DeploymentNetworkRealization",
    "ImageRealizationMode",
    "LOOPBACK_HOST_IP",
    "valid_environment_variable_name",
)
