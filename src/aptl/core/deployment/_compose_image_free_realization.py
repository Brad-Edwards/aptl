"""Image-free node partitioning and materialization (ADR-048, issue #581).

Split out of ``_compose_realization.py`` (module-length budget): the pure
helpers that decide which nodes convert to the generic materializer and
which Compose service names must be scaled to zero, plus the shared
materialize-a-node-subset entry point both the fully image-free and
mixed-realization paths dispatch through.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult


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
        replace(node, published_ports=()) if node.address in image_free_addresses else node
        for node in realization.nodes
    )
    return cast(DeploymentRealizationSpec, replace(realization, nodes=legacy_nodes))


def _image_free_node_addresses(realization: DeploymentRealizationSpec) -> frozenset[str]:
    """Return the addresses of every node declaring runtime desired state."""

    return frozenset(node.address for node in realization.nodes if node.runtime is not None)


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
) -> LabResult | None:
    """Materialize a node subset's declared state via the generic materializer.

    Shared by the fully image-free path and the mixed-realization path
    (ADR-048); the only difference between them is which nodes/content are
    passed in. Lowers each content item to its placement op and dispatches
    per node, verified by read-after-write.
    """

    from aptl.backends.aces_base_substrate import base_container_spec
    from aptl.backends.aces_materializer import PlaceFileOp, PlaceProjectContentOp
    from aptl.backends.aces_node_materialization import realize_nodes

    # A fresh machine has none of the locally-built generic base images in
    # its Docker cache (issue #581 - a developer's existing cache had
    # silently masked this gap since ADR-048 shipped). Ensure every image
    # this node subset needs exists once, up front, rather than having each
    # node's own start_base_container discover it missing one at a time.
    image_build_failures: list[str] = []
    for image_ref in sorted(
        {
            base_container_spec(
                node.address, os=node.os, os_version=node.os_version, runtime=node.runtime
            ).image_ref
            for node in nodes
        }
    ):
        image_build_failures.extend(backend.ensure_generic_base_image(image_ref))
    if image_build_failures:
        return LabResult(success=False, error="; ".join(image_build_failures[:5]))

    content_by_node: dict[str, list[object]] = {}
    for item in content:
        dest = "/" + item.dest_relpath.lstrip("/")
        if item.source_kind == "inline-text" and item.inline_text is not None:
            op: object = PlaceFileOp(path=dest, content=item.inline_text)
        elif item.source_kind in ("project-file", "project-directory") and item.source_relpath:
            op = PlaceProjectContentOp(
                dest_path=dest,
                source_relpath=item.source_relpath,
                is_directory=item.source_kind == "project-directory",
            )
        else:
            continue
        content_by_node.setdefault(item.target_address, []).append(op)
    return realize_nodes(
        nodes,
        backend,
        {addr: tuple(ops) for addr, ops in content_by_node.items()},
    )
