"""Typed deployment realization inputs for scenario-driven lab startup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ImageRealizationMode = Literal["pull", "build"]


@dataclass(frozen=True)
class DeploymentImageRealization(object):
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
class DeploymentNetworkRealization(object):
    """One scenario-declared network the deployment backend may materialize."""

    name: str
    cidr: str | None = None
    gateway: str | None = None
    internal: bool | None = None


@dataclass(frozen=True)
class DeploymentNetworkAttachment(object):
    """One node-to-network attachment requested by the scenario."""

    network: str
    ipv4_address: str | None = None


@dataclass(frozen=True)
class DeploymentNodeRealization(object):
    """One scenario-declared node bound to a backend-managed service."""

    address: str
    name: str
    service_name: str | None
    container_name: str | None
    networks: tuple[str, ...]
    network_attachments: tuple[DeploymentNetworkAttachment, ...] = ()


@dataclass(frozen=True)
class DeploymentRealizationSpec(object):
    """Portable input for typed deployment backend realization."""

    profiles: tuple[str, ...]
    nodes: tuple[DeploymentNodeRealization, ...]
    networks: tuple[DeploymentNetworkRealization, ...]
    images: tuple[DeploymentImageRealization, ...] = ()
