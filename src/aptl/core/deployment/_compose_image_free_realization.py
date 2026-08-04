"""Image-free node partitioning and materialization (ADR-048, issue #581).

Split out of ``_compose_realization.py`` (module-length budget): the pure
helpers that decide which nodes convert to the generic materializer and
which Compose service names must be scaled to zero, plus the shared
materialize-a-node-subset entry point both the fully image-free and
mixed-realization paths dispatch through.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.deployment.errors import BackendSeedError
from aptl.core.lab_types import LabResult

if TYPE_CHECKING:
    from aptl.backends.raes_base_substrate import VolumeMount


def _needs_compose(realization: DeploymentRealizationSpec) -> bool:
    """Whether any node is left for Compose to start.

    Derived from the nodes themselves rather than a spec-level flag, so a graph
    that mixes pinned artifacts, per-component builds and materialized nodes
    routes correctly instead of falling into a whole-graph special case.

    An empty graph keeps the Compose path: having no nodes is not the same as
    having materialized them all, and the Compose pipeline still owns networks,
    stateful prerequisites and validation.
    """

    if not realization.nodes:
        return True
    materialized = _image_free_node_addresses(realization)
    return any(
        node.address not in materialized and node.service_name
        for node in realization.nodes
    )


def _strip_image_free_published_ports(
    realization: DeploymentRealizationSpec, image_free_addresses: frozenset[str]
) -> DeploymentRealizationSpec:
    """Clear ``published_ports`` on nodes the generic materializer already started.

    An image-free node's declared host ports were already bound by its own
    ``docker run -p`` (``start_base_container``) during image-free
    materialization, which runs before the legacy Compose pipeline below.
    Left alone, that pipeline's own published-port conflict check and
    Compose port override would re-probe the same host port their own
    earlier stage already bound, failing the whole ``realize()`` call on a
    false conflict with itself (issue #581). The node's docker-compose.yml
    stub is also never started (``--scale=0``), so a Compose port override
    for it would be silently inert either way.
    """

    legacy_nodes = tuple(
        replace(node, published_ports=())
        if node.address in image_free_addresses
        else node
        for node in realization.nodes
    )
    return cast(DeploymentRealizationSpec, replace(realization, nodes=legacy_nodes))


def _image_free_node_addresses(
    realization: DeploymentRealizationSpec,
) -> frozenset[str]:
    """Return the addresses of nodes the generic materializer realizes from a base OS.

    A node is materialized image-free only when it declares runtime desired state
    *and* resolves to no backing image. A node that declares runtime inventory but
    also carries a real image -- ``suricata`` describing its detection engine while
    still pulling ``jasonish/suricata``, ``wazuh-manager`` describing its SIEM while
    pulling ``wazuh/wazuh-manager`` -- is an image node whose Compose service must
    start, not a bare-OS node to stub.

    Keying on ``runtime`` alone silently scaled those services to zero and started
    a ``debian:12-slim`` ``sleep infinity`` substrate in their place, so declaring
    a node's security tooling turned the actual tool off. The image check is the
    same one the realization-time materializable test applies
    (``_is_materializable_node``); the two must agree, or a node is realized one
    way here and scaled the other way there.
    """

    imaged = {image.address for image in realization.images}
    return frozenset(
        node.address
        for node in realization.nodes
        if node.runtime is not None and node.address not in imaged
    )


def _image_free_service_names(
    realization: DeploymentRealizationSpec, image_free_addresses: frozenset[str]
) -> tuple[str, ...]:
    """Return the Compose service names of nodes materialized directly (ADR-048).

    These must be scaled to zero when Compose starts the rest of the
    realization: they were already realized by the generic materializer, and
    starting them again as Compose containers would either collide on the
    shared container name or silently duplicate the node.
    """

    return tuple(
        sorted(
            node.service_name
            for node in realization.nodes
            if node.address in image_free_addresses and node.service_name
        )
    )


def _realize_node_subset(
    backend: object,
    nodes: tuple[object, ...],
    content: tuple[object, ...],
    scenario_root: Path,
    extra_ops: dict[str, tuple[object, ...]] | None = None,
    persistent_volumes: tuple[object, ...] = (),
) -> LabResult | None:
    """Materialize a node subset's declared state via the generic materializer.

    Shared by the fully image-free path and the mixed-realization path
    (ADR-048); the only difference between them is which nodes/content are
    passed in. Lowers each content item to its placement op and dispatches
    per node, verified by read-after-write. ``extra_ops`` carries additional
    per-node placement ops (a consumer's generated-artifact outputs, #875)
    already keyed by node address. ``persistent_volumes`` carries the
    realization's persistent volumes so an image-free node that consumes one
    mounts it: the Compose override defers non-Compose consumers to this
    materializer rather than declaring a mount no Compose service carries
    (issue #875).
    """

    from aptl.backends.raes_node_materialization import realize_nodes

    volume_mounts_by_node = _volume_mounts_by_node(nodes, persistent_volumes)
    image_build_failures = _ensure_generic_base_images(backend, nodes)
    if image_build_failures:
        return LabResult(success=False, error="; ".join(image_build_failures[:5]))
    network_failure = _bind_base_container_networks(backend, nodes)
    if network_failure is not None:
        return network_failure

    content_by_node = _content_ops_by_node(content)
    for address, ops in (extra_ops or {}).items():
        content_by_node.setdefault(address, []).extend(ops)
    return realize_nodes(
        nodes,
        backend,
        {addr: tuple(ops) for addr, ops in content_by_node.items()},
        scenario_root=scenario_root,
        volume_mounts_by_node=volume_mounts_by_node,
    )


def _volume_mounts_by_node(
    nodes: tuple[object, ...],
    persistent_volumes: tuple[object, ...],
) -> dict[str, tuple[VolumeMount, ...]]:
    """Return each node's declared persistent-volume mounts, keyed by address.

    Consumers outside this node subset are skipped: a volume shared with a
    Compose service is mounted there by the Compose override, not here.
    """

    from aptl.backends.raes_base_substrate import VolumeMount

    node_addresses = {node.address for node in nodes}
    mounts: dict[str, tuple[VolumeMount, ...]] = {}
    for volume in persistent_volumes:
        for consumer in getattr(volume, "consumers", ()):
            address = consumer.target_address
            if address not in node_addresses:
                continue
            mounts.setdefault(address, ())
            mounts[address] += (
                VolumeMount(
                    target=consumer.mount_destination,
                    source=volume.name,
                    read_only=consumer.access_mode == "read_only",
                ),
            )
    return mounts


def _ensure_generic_base_images(
    backend: object, nodes: tuple[object, ...]
) -> list[str]:
    """Build every generic base image this node subset needs, up front.

    A fresh machine has none of the locally-built generic base images in
    its Docker cache (issue #581 - a developer's existing cache had
    silently masked this gap since ADR-048 shipped). Ensure every image
    this node subset needs exists once, up front, rather than having each
    node's own start_base_container discover it missing one at a time.
    """

    from aptl.backends.raes_base_substrate import base_container_spec

    failures: list[str] = []
    for image_ref in sorted(
        {
            base_container_spec(
                node.address,
                os=node.os,
                os_version=node.os_version,
                runtime=node.runtime,
            ).image_ref
            for node in nodes
        }
    ):
        failures.extend(backend.ensure_generic_base_image(image_ref))
    return failures


def _bind_base_container_networks(
    backend: object, nodes: tuple[object, ...]
) -> LabResult | None:
    """Attach the node subset to its declared networks, if the backend can."""

    configure_networks = getattr(backend, "configure_base_container_networks", None)
    if not callable(configure_networks):
        return None
    try:
        configure_networks(nodes)
    except BackendSeedError:
        return LabResult(
            success=False,
            error="Image-free network binding failed.",
        )
    return None


def _content_ops_by_node(content: tuple[object, ...]) -> dict[str, list[object]]:
    """Lower each content item to a placement op, keyed by target node address."""

    by_node: dict[str, list[object]] = {}
    for item in content:
        op = _content_placement_op(item)
        if op is not None:
            by_node.setdefault(item.target_address, []).append(op)
    return by_node


def _content_placement_op(item: object) -> object | None:
    """Return one content item's materializer placement op, or ``None``.

    A source kind that carries nothing placeable (an incomplete pack reference,
    an unset project path) lowers to ``None`` and is skipped.
    """

    from aptl.backends.raes_materializer import (
        PlaceFileOp,
        PlacePackArtifactOp,
        PlaceProjectContentOp,
    )

    dest = "/" + item.dest_relpath.lstrip("/")
    op: object | None = None
    if item.source_kind == "inline-text" and item.inline_text is not None:
        op = PlaceFileOp(path=dest, content=item.inline_text)
    elif (
        item.source_kind in ("pack-file", "pack-directory")
        and item.artifact_id
        and item.artifact_digest
    ):
        op = PlacePackArtifactOp(
            dest_path=dest,
            artifact_id=item.artifact_id,
            artifact_digest=item.artifact_digest,
            is_directory=item.source_kind == "pack-directory",
        )
    elif (
        item.source_kind in ("project-file", "project-directory")
        and item.source_relpath
    ):
        op = PlaceProjectContentOp(
            dest_path=dest,
            source_relpath=item.source_relpath,
            is_directory=item.source_kind == "project-directory",
        )
    return op
