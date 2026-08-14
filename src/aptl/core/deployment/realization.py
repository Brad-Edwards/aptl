"""Typed deployment realization inputs for scenario-driven lab startup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from raes.runtime_configuration import RuntimeConfiguration


ImageRealizationMode = Literal["pull", "build"]
StatefulConsumerAccessMode = Literal["read_only", "read_write"]
GeneratedArtifactKind = Literal[
    "certificate_bundle", "rendered_config", "ssh_key_bundle"
]
GeneratedArtifactLifecycle = Literal["regenerate_on_change", "reuse_valid"]
GeneratedArtifactOutputDisposition = Literal["consumer_selected", "producer_private"]
ResourceSensitivity = Literal["public", "restricted", "secret"]
VolumeLifecycle = Literal["retain", "ephemeral"]
VolumeAccessMode = Literal["read_write_once", "read_write_many", "read_only_many"]
AclDirection = Literal["in", "out", "inout"]
AclAction = Literal["allow", "deny"]
AclProtocol = Literal["any", "tcp", "udp", "icmp"]

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
class DeploymentAclRealization(object):
    """One admitted RAES infrastructure ACL lowered for backend enforcement."""

    owner_address: str
    owner_resource_type: Literal["node", "network"]
    owner_name: str
    name: str
    order: int
    direction: AclDirection
    from_network: str | None
    to_network: str | None
    protocol: AclProtocol
    ports: tuple[int, ...]
    action: AclAction

    def details(self) -> dict[str, object]:
        return {
            "owner_address": self.owner_address,
            "owner_resource_type": self.owner_resource_type,
            "owner_name": self.owner_name,
            "name": self.name,
            "order": self.order,
            "direction": self.direction,
            "from_network": self.from_network,
            "to_network": self.to_network,
            "protocol": self.protocol,
            "ports": list(self.ports),
            "action": self.action,
        }


@dataclass(frozen=True)
class DeploymentServicePort(object):
    """One node-local transport binding declared on a RAES node.

    Mirrors RAES ``ServicePort``: a container-facing service identity. It does
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

    Mirrors RAES ``RuntimePublishedPort``. ``host_ip`` is the host-facing
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
    ordering_dependencies: tuple[str, ...] = ()
    # ADR-048: declared desired state the generic materializer realizes onto a
    # base substrate. None until the node payload declares them.
    os: str = ""
    os_version: str = ""
    runtime: RuntimeConfiguration | None = None
    # ADR-051 route 3 (issue #876): started immutably from the verified config id
    # (never a pull, never a moved tag) when the node authored an open
    # dynamic-composition source.
    dynamic_composition: bool = False
    # Deployment-serving membership is resolved once by the pack/backend
    # interaction seam and copied through the DTO. Renderers never rediscover it
    # from component names.
    profiles: tuple[str, ...] = ()


ContentSourceKind = Literal[
    "inline-text",
    "project-file",
    "project-directory",
    "empty-directory",
    "pack-file",
    "pack-directory",
]


@dataclass(frozen=True)
class DeploymentContentRealization(object):
    """One content-placement operation lowered from a RAES content resource.

    ``source_kind`` records how the content is materialized: ``inline-text``
    (bounded text carried on the placement itself), ``project-file`` /
    ``project-directory`` (a checked-in, project-contained source path),
    ``empty-directory`` (an explicit empty-directory declaration with no
    source), or ``pack-file`` / ``pack-directory`` (bytes resolved from a
    validated env-pack by opaque ``artifact_id`` + ``sha256`` ``artifact_digest``
    through ``resolve_pack_artifact``; a ``pack-directory`` artifact is an
    ``application/x-tar`` archive extracted at the destination). ``source_relpath``
    is project-relative and only set for the two project-sourced kinds;
    ``inline_text`` is only set for ``inline-text``; ``artifact_id`` /
    ``artifact_digest`` / ``media_type`` are only set for the two pack kinds.
    These are mutually exclusive by construction in the interpreter.
    """

    address: str
    target_address: str
    content_name: str
    volume_suffix: str
    dest_relpath: str
    source_kind: ContentSourceKind
    source_relpath: str | None = None
    inline_text: str | None = None
    artifact_id: str | None = None
    artifact_digest: str | None = None
    media_type: str | None = None
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
            "artifact_id": self.artifact_id,
            "artifact_digest": self.artifact_digest,
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True)
class DeploymentServiceSearchIndexSchemaRealization(object):
    """One ADR-088 ``service-search-index-schema`` materialization lowered from a
    RAES content-placement that carries a ``service_materialization`` binding.

    The portable logical store is the canonical content ``address`` bound to the
    exact ``target_service_address``; the concrete native index name is resolved
    from the backend adapter configuration, never authored in SDL (ADR-088 keeps
    native ids out of the portable contract). ``field_semantics`` maps portable
    top-level field names to the closed portable semantic set
    (``exact-token`` / ``full-text`` / ``integer`` / ``temporal`` / ``boolean``);
    the backend projects each to a native field type, materializes the schema
    through the service's native interface, and proves it by fresh native
    readback whose portable projection reproduces ``field_schema_digest`` (the
    RAES-compiled ``canonical_field_schema_digest``).

    ``field_semantics`` is a name-sorted tuple of ``(field, semantic)`` pairs so
    the record stays hashable/immutable; :meth:`field_semantics_map` returns the
    mapping the provider consumes.
    """

    address: str
    target_address: str
    target_service_address: str
    content_name: str
    field_semantics: tuple[tuple[str, str], ...]
    field_schema_digest: str

    def field_semantics_map(self) -> dict[str, str]:
        return dict(self.field_semantics)

    def details(self) -> dict[str, object]:
        # Portable identifiers, the declared semantics, and the digest only — no
        # native index name, endpoint, query, or response body crosses this
        # record (ADR-088 / issue #889 redaction boundary).
        return {
            "address": self.address,
            "target_address": self.target_address,
            "target_service_address": self.target_service_address,
            "content_name": self.content_name,
            "field_semantics": dict(self.field_semantics),
            "field_schema_digest": self.field_schema_digest,
        }


@dataclass(frozen=True)
class DeploymentAccountRealization(object):
    """One account-placement identity lowered from a RAES account resource.

    Carries non-secret identity only (ADR-046 addendum): no password material
    crosses this record. The concrete credential is generated inside the target
    provider boundary and never disclosed; this record is realization evidence
    proving the declared account maps to a node whose backend provider actually
    creates and reconciles it.

    Author explicitness is preserved for optional attributes so the backend
    reconciles only what the scenario author declared (SEM-218, ADR-046
    addendum): ``mail`` / ``spn`` are ``""`` when the author omitted them, and
    ``disabled`` is ``None`` when omitted (distinct from an authored ``False``).
    An omitted attribute is never materialized, so a benign placement cannot
    silently flip an existing account's state.
    """

    address: str
    target_address: str
    username: str
    groups: tuple[str, ...] = ()
    spn: str = ""
    mail: str = ""
    disabled: bool | None = None

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
class DeploymentStatefulConsumer(object):
    """One resolved node mount for a generated artifact or persistent volume.

    ``selected_outputs`` names the generated-artifact outputs this consumer
    receives; empty for persistent volumes and for generated artifacts that
    expose every consumer-selectable output. A ``producer_private`` output is
    never selectable and never mounted, regardless of this list.
    """

    target_address: str
    node_name: str
    service_name: str
    mount_destination: str
    access_mode: StatefulConsumerAccessMode
    selected_outputs: tuple[str, ...] = ()

    def details(self) -> dict[str, object]:
        return {
            "target_address": self.target_address,
            "node_name": self.node_name,
            "service_name": self.service_name,
            "mount_destination": self.mount_destination,
            "access_mode": self.access_mode,
            "selected_outputs": list(self.selected_outputs),
        }


@dataclass(frozen=True)
class DeploymentGeneratedArtifactOutput(object):
    """One declared output from a backend-owned generated artifact.

    ``disposition`` is ``producer_private`` for material that must stay on the
    producer and never be mounted into any consumer (a CA private key, the
    control-plane SSH key), or ``consumer_selected`` for material a consumer may
    receive by naming it in its ``selected_outputs``.
    """

    name: str
    path: str
    sensitivity: ResourceSensitivity
    disposition: GeneratedArtifactOutputDisposition = "consumer_selected"

    def details(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "sensitivity": self.sensitivity,
            "disposition": self.disposition,
        }


@dataclass(frozen=True)
class DeploymentGeneratedArtifactRealization(object):
    """One RAES generated-artifact operation admitted for deployment."""

    address: str
    name: str
    generator: GeneratedArtifactKind
    lifecycle: GeneratedArtifactLifecycle
    provenance: str
    outputs: tuple[DeploymentGeneratedArtifactOutput, ...]
    consumers: tuple[DeploymentStatefulConsumer, ...]
    ordering_dependencies: tuple[str, ...] = ()
    refresh_dependencies: tuple[str, ...] = ()

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "generator": self.generator,
            "lifecycle": self.lifecycle,
            "provenance": self.provenance,
            "outputs": [output.details() for output in self.outputs],
            "consumers": [consumer.details() for consumer in self.consumers],
            "ordering_dependencies": list(self.ordering_dependencies),
            "refresh_dependencies": list(self.refresh_dependencies),
        }


@dataclass(frozen=True)
class DeploymentPersistentVolumeRealization(object):
    """One RAES persistent-volume operation admitted for deployment."""

    address: str
    name: str
    lifecycle: VolumeLifecycle
    access_mode: VolumeAccessMode
    consumers: tuple[DeploymentStatefulConsumer, ...]
    ordering_dependencies: tuple[str, ...] = ()
    refresh_dependencies: tuple[str, ...] = ()

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "lifecycle": self.lifecycle,
            "access_mode": self.access_mode,
            "consumers": [consumer.details() for consumer in self.consumers],
            "ordering_dependencies": list(self.ordering_dependencies),
            "refresh_dependencies": list(self.refresh_dependencies),
        }


@dataclass(frozen=True)
class DeploymentRealizationSpec(object):
    """Portable input for typed deployment backend realization."""

    profiles: tuple[str, ...]
    nodes: tuple[DeploymentNodeRealization, ...]
    networks: tuple[DeploymentNetworkRealization, ...]
    acls: tuple[DeploymentAclRealization, ...] = ()
    images: tuple[DeploymentImageRealization, ...] = ()
    content: tuple[DeploymentContentRealization, ...] = ()
    accounts: tuple[DeploymentAccountRealization, ...] = ()
    service_index_schemas: tuple[DeploymentServiceSearchIndexSchemaRealization, ...] = ()
    generated_artifacts: tuple[DeploymentGeneratedArtifactRealization, ...] = ()
    persistent_volumes: tuple[DeploymentPersistentVolumeRealization, ...] = ()
    # ADR-048 image-free materialization is no longer a whole-spec flag: routing
    # is derived per node at realize() time (``_needs_compose`` /
    # ``_image_free_node_addresses``) so a graph that mixes pinned artifacts,
    # per-component builds and materialized nodes routes each node correctly
    # rather than falling into a single whole-graph decision.
