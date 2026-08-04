"""Docker Compose realization orchestration for typed deployment specs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

from aptl.core.deployment._compose_account_realization import (
    ComposeRealizationAccountMixin,
)
from aptl.core.deployment._compose_content_realization import (
    ComposeRealizationContentMixin,
)
from aptl.core.deployment._compose_boundary_realization import (
    ComposeBoundaryRealizationMixin,
)
from aptl.core.deployment._compose_model_realization import (
    ComposeRealizationModelMixin,
)
from aptl.core.deployment._compose_node_generation import STATIC_COMPOSE_FILENAME
from aptl.core.deployment._compose_post_start import (
    ComposeRealizationPostStartMixin,
)
from aptl.core.deployment._compose_port_realization import published_port_conflicts
from aptl.core.deployment._compose_stateful_realization import (
    ComposeStatefulRealizationMixin,
)
from aptl.core.deployment._compose_image_realization import (
    ComposeRealizationImageMixin,
)
from aptl.core.deployment._compose_network_realization import (
    ComposeRealizationNetworkMixin,
)
from aptl.core.deployment._compose_image_free_realization import (
    _image_free_node_addresses,
    _image_free_service_names,
    _needs_compose,
    _realize_node_subset,
    _strip_image_free_published_ports,
)
from aptl.core.deployment._compose_realization_networks import (
    _container_networks,
    _network_name_candidates,
    _resolve_realization_networks,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult

__all__ = [
    "ComposeRealizationMixin",
    "_container_networks",
    "_image_free_node_addresses",
    "_image_free_service_names",
    "_network_name_candidates",
    "_realize_node_subset",
    "_resolve_realization_networks",
    "_strip_image_free_published_ports",
]


class ComposeRealizationMixin(
    ComposeBoundaryRealizationMixin,
    ComposeRealizationImageMixin,
    ComposeRealizationNetworkMixin,
    ComposeRealizationContentMixin,
    ComposeRealizationAccountMixin,
    ComposeRealizationModelMixin,
    ComposeRealizationPostStartMixin,
    ComposeStatefulRealizationMixin,
):
    """Realize typed scenario specs through Docker Compose."""

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
        scenario_root: Path,
        substrate_digests: Mapping[str, str] | None = None,
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose.

        ``scenario_root`` is the bundle root every scenario-declared filesystem
        input (Compose model, build contexts, generated-artifact locations)
        resolves against. It is required and request-scoped: the backend never
        caches it. The operator ``.env`` stays the control-plane
        ``project_dir/.env``. For an in-tree scenario ``scenario_root`` is the
        project directory, so behaviour is unchanged (issue #874).

        ``substrate_digests`` carries the address-scoped immutable substrate
        identity the availability pass already verified for each
        dynamic-composition node (issue #876 cycle-6 review). It is stored as
        request-scoped apply context and consumed by ``start_base_container`` so a
        route-3 node starts from exactly that config id, never a second
        resolution of the mutable tag.
        """

        # Request-scoped, like the network bindings below: the base start reads it
        # by node address and never re-resolves the tag it was verified from.
        self._realization_substrate_digests = dict(substrate_digests or {})
        # Route from per-node facts, never a whole-graph flag. A mixed graph is
        # normal (ADR-051): some nodes come from a pinned artifact, some are
        # built from a specification, some are composed from declared state. The
        # only whole-graph question left is whether Compose has anything to
        # start.
        if not _needs_compose(realization):
            return self._realize_without_compose(realization, scenario_root)
        return self._realize_mixed_or_legacy(
            realization, build=build, scenario_root=scenario_root
        )

    def _realize_mixed_or_legacy(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool,
        scenario_root: Path,
    ) -> LabResult:
        """Realize a spec with at least one still-Compose-managed node.

        Covers both shapes: fully legacy (nothing image-free) and mixed
        (ADR-048's image-free subset materialized first, then the legacy
        Compose pipeline for the rest).
        """

        image_free_addresses = _image_free_node_addresses(realization)
        if image_free_addresses:
            # Mixed realization (ADR-048): materialize the runtime:-declared
            # subset directly first - it never becomes a Compose container -
            # then run the legacy pipeline for the rest, with those service
            # names excluded from `compose up` so neither side starts, skips,
            # or double-realizes the other's nodes.
            node_result = self._materialize_image_free_nodes(
                realization, image_free_addresses, scenario_root, self._project_dir
            )
            if node_result is not None:
                return node_result
            # ``--scale <svc>=0`` keeps Compose from starting an image-free node's
            # stub, but only when that stub exists. A static in-tree
            # docker-compose.yml declares every node, so its image-free stubs must
            # be scaled to zero; a generated env-pack base contains only image
            # nodes, so scaling an absent service errors ("no such service")
            # (issue #875).
            excluded_services = (
                _image_free_service_names(realization, image_free_addresses)
                if (scenario_root / STATIC_COMPOSE_FILENAME).exists()
                else ()
            )
            legacy_content = tuple(
                item
                for item in realization.content
                if item.target_address not in image_free_addresses
            )
            realization = cast(
                DeploymentRealizationSpec, replace(realization, content=legacy_content)
            )
            realization = _strip_image_free_published_ports(
                realization, image_free_addresses
            )
        else:
            excluded_services = ()

        profiles = list(realization.profiles)
        compose_files: tuple[Path, ...] | None = None
        # Generated realization output (base compose, overrides, generated
        # artifacts) is written under the writable engine checkout, never under
        # the pristine staged pack whose digest-validated inventory must not gain
        # generated files (issue #875). In-tree the two roots coincide. This is
        # the backend's published root so realization observation reads the
        # artifacts back from the same place they were written.
        realization_root = self.realization_root

        def _images() -> LabResult | None:
            """Pull/build declared images and capture the resulting compose override."""

            nonlocal compose_files
            result, compose_files = self._prepare_realization_images(
                realization, scenario_root, realization_root
            )
            return result

        def _compose_model() -> LabResult | None:
            """Render and validate the generated Compose model."""

            nonlocal compose_files
            compose_files = self._realization_compose_files(
                compose_files, realization, scenario_root, realization_root
            )
            return self._validate_realization_compose_model(
                profiles, compose_files, realization, scenario_root, realization_root
            )

        def _start() -> LabResult:
            """Start the realized services and return the final realization result."""

            start_result = self._start_realized_services(
                profiles,
                build=build and not self._offline_staged,
                compose_files=compose_files,
                exclude_services=excluded_services,
                scenario_root=scenario_root,
            )
            return self._realization_result(start_result, realization)

        # Each step realizes one stage and returns a fail-closed LabResult, or
        # None to fall through to the next stage. The last stage always
        # returns, so the pipeline always ends in a concrete result.
        steps = (
            lambda: self._validate_stateful_realization(realization),
            lambda: self._validate_stateful_compose_capability(realization),
            lambda: self._realize_stateful_prerequisites(realization, realization_root),
            _images,
            lambda: self._realize_published_ports(realization),
            lambda: self._realize_networks_and_boundaries(realization),
            lambda: self._realize_content(realization, scenario_root),
            _compose_model,
            _start,
        )
        for step in steps:
            result = step()
            if result is not None:
                return result
        return LabResult(success=True)

    def _realize_networks_and_boundaries(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Ensure declared networks exist, then realize authority boundaries.

        Fails closed on the first network error rather than continuing into
        boundary realization on a topology that was never brought up. Returns
        ``None`` when both stages succeed, so callers chain on ``is not None``.
        """

        network_failures = self._ensure_realization_networks(realization)
        if network_failures:
            return LabResult(success=False, error="; ".join(network_failures[:5]))
        return self._realize_authority_boundaries(realization)

    def _materialize_image_free_nodes(
        self,
        realization: DeploymentRealizationSpec,
        addresses: frozenset[str],
        scenario_root: Path,
        realization_root: Path | None = None,
    ) -> LabResult | None:
        """Materialize just the runtime:-declared node subset (ADR-048).

        Shares the same node materialization and content-op lowering as the
        fully image-free path, scoped to ``addresses`` so mixed-realization
        content meant for a Compose-managed node is never misinterpreted as
        an image-free placement. Content is read from ``scenario_root`` (the
        pack); generated artifacts are written under ``realization_root`` (the
        writable engine checkout) — issue #875.
        """

        realization_root = realization_root or scenario_root
        substrate_failure = self._realize_networks_and_boundaries(realization)
        if substrate_failure is not None:
            return substrate_failure
        nodes = tuple(n for n in realization.nodes if n.address in addresses)
        content = tuple(
            item for item in realization.content if item.target_address in addresses
        )
        failure, extra_ops = self._image_free_generated_artifact_ops(
            realization, addresses, realization_root
        )
        if failure is not None:
            return failure
        return _realize_node_subset(
            self,
            nodes,
            content,
            scenario_root,
            extra_ops,
            persistent_volumes=realization.persistent_volumes,
        )

    def _image_free_generated_artifact_ops(
        self,
        realization: DeploymentRealizationSpec,
        addresses: frozenset[str],
        realization_root: Path,
    ) -> tuple[LabResult | None, dict[str, tuple[object, ...]]]:
        """Generate and lower each image-free consumer's generated-artifact outputs.

        Compose nodes receive generated artifacts as bind mounts; an image-free
        node has no Compose service to mount into, so its consumer's selected,
        non-producer-private outputs are placed into the container as files
        instead (issue #875). The artifact is generated under ``realization_root``
        (never the pristine pack) once here, before the node is materialized, so
        its outputs exist to place; the generators are idempotent, so a later
        compose-side generation reuses the same material.
        """

        ops_by_address: dict[str, list[object]] = {}
        for artifact in realization.generated_artifacts:
            consumers = [
                consumer
                for consumer in artifact.consumers
                if consumer.target_address in addresses
            ]
            if not consumers:
                continue
            failure = self._realize_one_generated_artifact(artifact, realization_root)
            if failure is None:
                failure = _append_image_free_artifact_ops(
                    ops_by_address, artifact, consumers, realization_root
                )
            if failure is not None:
                return failure, {}
        return None, {addr: tuple(ops) for addr, ops in ops_by_address.items()}

    def _realize_without_compose(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> LabResult:
        """Realize a graph in which no node is Compose-managed.

        Every node is materialized from declared state onto a generic base
        substrate, so there is nothing for ``compose up`` to start.

        Networks first, then each node's declared packages/identity/services are
        materialized and verified by read-after-write, then content placements.
        Fails closed on the first unrealized node so a partial range never
        reports success.
        """

        substrate_failure = self._realize_networks_and_boundaries(realization)
        if substrate_failure is not None:
            return substrate_failure
        addresses = frozenset(node.address for node in realization.nodes)
        failure, extra_ops = self._image_free_generated_artifact_ops(
            realization, addresses, self.realization_root
        )
        if failure is not None:
            return failure
        node_result = _realize_node_subset(
            self,
            realization.nodes,
            realization.content,
            scenario_root,
            extra_ops,
            persistent_volumes=realization.persistent_volumes,
        )
        return node_result if node_result is not None else LabResult(success=True)

    def _realize_published_ports(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Refuse to start when a declared exact host binding cannot be published.

        Checked before anything is started so a port conflict fails the run
        cleanly rather than half-realizing the topology. A scenario-declared host
        port is a realization requirement, so it fails closed instead of being
        remapped the way the checked-in stack's convenience ports are.
        """

        conflicts = published_port_conflicts(realization)
        if not conflicts:
            return None
        return LabResult(success=False, error="; ".join(conflicts[:5]))


def _append_image_free_artifact_ops(
    ops_by_address: dict[str, list[object]],
    artifact: object,
    consumers: list[object],
    realization_root: Path,
) -> LabResult | None:
    """Lower one artifact's per-consumer outputs into placement ops.

    Each selected, non-producer-private output becomes a file placement under
    the consumer's declared mount destination, with a secret output placed
    owner-only. Returns a fail-closed result when a declared output was not
    produced, so an image-free node never starts missing material it declared.
    """

    from pathlib import PurePosixPath

    from aptl.backends.raes_materializer import PlaceFileOp
    from aptl.core.deployment._compose_stateful_model import (
        _consumer_output_names,
        artifact_source_path,
    )

    source = artifact_source_path(realization_root, artifact)
    by_name = {output.name: output for output in artifact.outputs}
    for consumer in consumers:
        for name in _consumer_output_names(artifact, consumer):
            output = by_name[name]
            try:
                content = (source / output.path).read_text(encoding="utf-8")
            except OSError:
                return LabResult(
                    success=False,
                    error=(
                        "Generated artifact output missing for image-free "
                        f"consumer {consumer.target_address}: {output.path}."
                    ),
                )
            destination = str(PurePosixPath(consumer.mount_destination) / output.path)
            mode = "0600" if output.sensitivity == "secret" else "0644"
            ops_by_address.setdefault(consumer.target_address, []).append(
                PlaceFileOp(path=destination, content=content, mode=mode)
            )
    return None
