"""Typed deployment realization inputs for scenario-driven lab startup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ImageRealizationMode = Literal["pull", "build"]

# An SDL-declared host publish with no author-supplied host address binds
# loopback. Defaulting to all interfaces would silently put a scenario-declared
# port on the operator's LAN (ADR-034 Host Exposure Amendment); an author who
# wants that must say so with an explicit host_ip.
LOOPBACK_HOST_IP = "127.0.0.1"


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
class DeploymentServicePort(object):
    """One node-local transport binding declared on an ACES node.

    Mirrors ACES ``ServicePort``: a container-facing service identity. It does
    not publish a host port and does not authorize traffic — host exposure is
    :class:`DeploymentPublishedPort`, a deliberately separate surface (ADR-025).
    """

    name: str
    port: int
    protocol: str = "tcp"

    def details(self) -> dict[str, object]:
        return {"name": self.name, "port": self.port, "protocol": self.protocol}


@dataclass(frozen=True)
class DeploymentPublishedPort(object):
    """One host-published port binding declared on a node's runtime network.

    Mirrors ACES ``RuntimePublishedPort``. ``host_ip`` is the host-facing
    exposure boundary: an author who omits it gets loopback, never all
    interfaces (ADR-034 Host Exposure Amendment). ``host_port`` is ``None`` when
    the author declared a container port with no fixed host binding.
    """

    container_port: int
    protocol: str = "tcp"
    host_ip: str = LOOPBACK_HOST_IP
    host_port: int | None = None

    def details(self) -> dict[str, object]:
        return {
            "container_port": self.container_port,
            "protocol": self.protocol,
            "host_ip": self.host_ip,
            "host_port": self.host_port,
        }


@dataclass(frozen=True)
class DeploymentNodeRealization(object):
    """One scenario-declared node bound to a backend-managed service."""

    address: str
    name: str
    service_name: str | None
    container_name: str | None
    networks: tuple[str, ...]
    network_attachments: tuple[DeploymentNetworkAttachment, ...] = ()
    services: tuple[DeploymentServicePort, ...] = ()
    published_ports: tuple[DeploymentPublishedPort, ...] = ()


ContentSourceKind = Literal[
    "inline-text", "project-file", "project-directory", "empty-directory"
]


@dataclass(frozen=True)
class DeploymentContentRealization(object):
    """One content-placement operation lowered from an ACES content resource.

    ``source_kind`` records how the content is materialized: ``inline-text``
    (bounded text carried on the placement itself), ``project-file`` /
    ``project-directory`` (a checked-in, project-contained source path), or
    ``empty-directory`` (an explicit empty-directory declaration with no
    source). ``source_relpath`` is project-relative and only set for the two
    project-sourced kinds; ``inline_text`` is only set for ``inline-text``.
    Both are mutually exclusive by construction in the interpreter.
    """

    address: str
    target_address: str
    content_name: str
    volume_suffix: str
    dest_relpath: str
    source_kind: ContentSourceKind
    source_relpath: str | None = None
    inline_text: str | None = None
    sensitive: bool = False

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "target_address": self.target_address,
            "content_name": self.content_name,
            "volume_suffix": self.volume_suffix,
            "dest_relpath": self.dest_relpath,
            "source_kind": self.source_kind,
            "source_relpath": self.source_relpath,
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True)
class DeploymentAccountRealization(object):
    """One account-placement identity lowered from an ACES account resource.

    Carries non-secret identity only (ADR-046 TechVault addendum): no
    password material crosses this record. The concrete credential stays
    owned by the target node's service-owned provisioner (e.g.
    ``containers/ad/provision-users.sh``); this record is realization
    evidence proving the declared account maps to a node whose backend
    service actually provisions it.
    """

    address: str
    target_address: str
    username: str
    groups: tuple[str, ...] = ()
    spn: str = ""
    mail: str = ""
    disabled: bool = False

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "target_address": self.target_address,
            "username": self.username,
            "groups": list(self.groups),
            "spn": self.spn,
            "mail": self.mail,
            "disabled": self.disabled,
        }


@dataclass(frozen=True)
class DeploymentRealizationSpec(object):
    """Portable input for typed deployment backend realization."""

    profiles: tuple[str, ...]
    nodes: tuple[DeploymentNodeRealization, ...]
    networks: tuple[DeploymentNetworkRealization, ...]
    images: tuple[DeploymentImageRealization, ...] = ()
    content: tuple[DeploymentContentRealization, ...] = ()
    accounts: tuple[DeploymentAccountRealization, ...] = ()
