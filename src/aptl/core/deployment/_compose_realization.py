"""Docker Compose realization orchestration for typed deployment specs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

from aptl.core.deployment._compose_account_realization import (
    ComposeRealizationAccountMixin,
)
from aptl.core.deployment._compose_content_realization import (
    CONTENT_SEEDER_IMAGE,
    ComposeRealizationContentMixin,
)
from aptl.core.deployment._compose_boundary_realization import (
    ComposeBoundaryRealizationMixin,
)
from aptl.core.deployment._compose_node_generation import base_compose_file
from aptl.core.deployment._compose_port_realization import (
    published_port_conflicts,
    write_port_override,
)
from aptl.core.deployment._compose_service_health import wait_for_realized_health
from aptl.core.deployment._compose_stateful_realization import (
    ComposeStatefulRealizationMixin,
    effective_stateful_model_errors,
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
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
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

_COMPOSE_MODEL_VALIDATION_ERROR = "Generated Compose model validation failed."


class ComposeRealizationMixin(
    ComposeBoundaryRealizationMixin,
    ComposeRealizationImageMixin,
    ComposeRealizationNetworkMixin,
    ComposeRealizationContentMixin,
    ComposeRealizationAccountMixin,
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
                realization, image_free_addresses, scenario_root
            )
            if node_result is not None:
                return node_result
            excluded_services = _image_free_service_names(
                realization, image_free_addresses
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

        def _images() -> LabResult | None:
            """Pull/build declared images and capture the resulting compose override."""

            nonlocal compose_files
            result, compose_files = self._prepare_realization_images(
                realization, scenario_root
            )
            return result

        def _networks() -> LabResult | None:
            """Ensure declared networks exist, or fail closed on the first error."""

            network_failures = self._ensure_realization_networks(realization)
            if network_failures:
                return LabResult(success=False, error="; ".join(network_failures[:5]))
            return self._realize_authority_boundaries(realization)

        def _compose_model() -> LabResult | None:
            """Render and validate the generated Compose model."""

            nonlocal compose_files
            compose_files = self._realization_compose_files(
                compose_files, realization, scenario_root
            )
            return self._validate_realization_compose_model(
                profiles, compose_files, realization, scenario_root
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
            lambda: self._realize_stateful_prerequisites(realization, scenario_root),
            _images,
            lambda: self._realize_published_ports(realization),
            _networks,
            lambda: self._realize_content(realization, scenario_root),
            _compose_model,
            _start,
        )
        for step in steps:
            result = step()
            if result is not None:
                return result
        return LabResult(success=True)

    def _materialize_image_free_nodes(
        self,
        realization: DeploymentRealizationSpec,
        addresses: frozenset[str],
        scenario_root: Path,
    ) -> LabResult | None:
        """Materialize just the runtime:-declared node subset (ADR-048).

        Shares the same node materialization and content-op lowering as the
        fully image-free path, scoped to ``addresses`` so mixed-realization
        content meant for a Compose-managed node is never misinterpreted as
        an image-free placement.
        """

        network_failures = self._ensure_realization_networks(realization)
        if network_failures:
            return LabResult(success=False, error="; ".join(network_failures[:5]))
        boundary_result = self._realize_authority_boundaries(realization)
        if boundary_result is not None:
            return boundary_result
        nodes = tuple(n for n in realization.nodes if n.address in addresses)
        content = tuple(
            item for item in realization.content if item.target_address in addresses
        )
        failure, extra_ops = self._image_free_generated_artifact_ops(
            realization, addresses, scenario_root
        )
        if failure is not None:
            return failure
        return _realize_node_subset(self, nodes, content, scenario_root, extra_ops)

    def _image_free_generated_artifact_ops(
        self,
        realization: DeploymentRealizationSpec,
        addresses: frozenset[str],
        scenario_root: Path,
    ) -> tuple[LabResult | None, dict[str, tuple[object, ...]]]:
        """Generate and lower each image-free consumer's generated-artifact outputs.

        Compose nodes receive generated artifacts as bind mounts; an image-free
        node has no Compose service to mount into, so its consumer's selected,
        non-producer-private outputs are placed into the container as files
        instead (issue #875). The artifact is generated once here (before the
        node is materialized) so its outputs exist to place; the generators are
        idempotent, so a later compose-side generation reuses the same material.
        """

        from pathlib import PurePosixPath

        from aptl.backends.raes_materializer import PlaceFileOp
        from aptl.core.deployment._compose_stateful_model import (
            _consumer_output_names,
            artifact_source_path,
        )

        ops_by_address: dict[str, list[object]] = {}
        for artifact in realization.generated_artifacts:
            consumers = [
                consumer
                for consumer in artifact.consumers
                if consumer.target_address in addresses
            ]
            if not consumers:
                continue
            failure = self._realize_one_generated_artifact(artifact, scenario_root)
            if failure is not None:
                return failure, {}
            source = artifact_source_path(scenario_root, artifact)
            by_name = {output.name: output for output in artifact.outputs}
            for consumer in consumers:
                for name in _consumer_output_names(artifact, consumer):
                    output = by_name[name]
                    origin = source / output.path
                    try:
                        content = origin.read_text(encoding="utf-8")
                    except OSError:
                        return (
                            LabResult(
                                success=False,
                                error=(
                                    "Generated artifact output missing for image-free "
                                    f"consumer {consumer.target_address}: {output.path}."
                                ),
                            ),
                            {},
                        )
                    destination = str(
                        PurePosixPath(consumer.mount_destination) / output.path
                    )
                    mode = "0600" if output.sensitivity == "secret" else "0644"
                    ops_by_address.setdefault(consumer.target_address, []).append(
                        PlaceFileOp(path=destination, content=content, mode=mode)
                    )
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

        network_failures = self._ensure_realization_networks(realization)
        if network_failures:
            return LabResult(success=False, error="; ".join(network_failures[:5]))
        boundary_result = self._realize_authority_boundaries(realization)
        if boundary_result is not None:
            return boundary_result
        addresses = frozenset(node.address for node in realization.nodes)
        failure, extra_ops = self._image_free_generated_artifact_ops(
            realization, addresses, scenario_root
        )
        if failure is not None:
            return failure
        node_result = _realize_node_subset(
            self, realization.nodes, realization.content, scenario_root, extra_ops
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

    def _realization_compose_files(
        self,
        compose_files: tuple[Path, ...] | None,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> tuple[Path, ...] | None:
        """Add generated realization overrides to the Compose file set.

        The base ``docker-compose.yml`` and the generated overrides are
        scenario-declared inputs, anchored to ``scenario_root`` (the bundle
        root), not the engine checkout.
        """

        port_override = write_port_override(scenario_root, realization)
        stateful_override = self._write_stateful_realization_override(
            realization, scenario_root
        )
        overrides = tuple(
            path for path in (port_override, stateful_override) if path is not None
        )
        if not overrides:
            return compose_files
        base_files = compose_files or (base_compose_file(realization, scenario_root),)
        return (*base_files, *overrides)

    def _realize_content(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> LabResult | None:
        """Materialize typed content placements; fail closed on any seed error.

        Returns ``None`` on success (or when there is nothing to realize) so
        the caller's ``result is None`` chain continues to the next step,
        matching the existing image/network step shape.
        """

        if not realization.content:
            return None
        try:
            self.realize_content(
                realization.content,
                seeder_image=CONTENT_SEEDER_IMAGE,
                scenario_root=scenario_root,
            )
        except (BackendSeedError, BackendTimeoutError) as exc:
            return LabResult(
                success=False,
                error=f"Content placement realization failed: {exc}",
            )
        return None

    def _validate_realization_compose_model(
        self,
        profiles: list[str],
        compose_files: tuple[Path, ...] | None,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> LabResult | None:
        """Render and inspect the effective generated model before startup."""

        if compose_files is None:
            return None
        command = self._build_command(
            "config",
            profiles,
            compose_files=compose_files,
            scenario_root=scenario_root,
        )
        stateful = bool(
            realization.generated_artifacts or realization.persistent_volumes
        )
        error = (
            self._effective_compose_model_error(command, realization, scenario_root)
            if stateful
            else self._compose_syntax_error(command)
        )
        return LabResult(success=False, error=error) if error is not None else None

    def _compose_syntax_error(self, command: list[str]) -> str | None:
        """Return a bounded error when Compose rejects a stateless model."""

        command.append("--quiet")
        result = self._run(command)
        return _COMPOSE_MODEL_VALIDATION_ERROR if result.returncode != 0 else None

    def _effective_compose_model_error(
        self,
        command: list[str],
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> str | None:
        """Render and validate a stateful model without interpolating secrets."""

        command.extend(["--no-interpolate", "--format", "json"])
        result = self._run(command)
        if result.returncode != 0:
            return _COMPOSE_MODEL_VALIDATION_ERROR
        try:
            payload = json.loads(result.stdout)
        except (TypeError, ValueError):
            return _COMPOSE_MODEL_VALIDATION_ERROR
        errors = effective_stateful_model_errors(
            payload,
            scenario_root,
            self.project_name,
            realization,
        )
        return "; ".join(errors[:5]) if errors else None

    def _realization_result(
        self,
        start_result: LabResult,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Return the final result after start, network, health, and accounts.

        Ordering is load-bearing: networks are reconciled, then services must be
        observed healthy, then accounts are realized. Account realization execs
        into the running node containers (``container_exec``), so it cannot run
        until those containers are up and healthy — the health wait gates it.
        """

        if not start_result.success:
            return start_result
        return self._post_start_result(realization)

    def _post_start_result(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Reconcile networks, await health, then realize accounts, in order.

        The steps are sequential and short-circuit: a network failure returns
        before the health wait runs, and accounts are realized only once the
        services are observed healthy (account realization execs into the running
        containers). First failure wins.
        """

        result: LabResult | None = None
        network_failures = self._reconcile_realization_networks(realization)
        if network_failures:
            result = LabResult(
                success=False,
                error="; ".join(network_failures[:5]),
            )
        if result is None:
            health_failures = self._await_realized_service_health(realization)
            if health_failures:
                result = LabResult(
                    success=False,
                    error="; ".join(health_failures[:5]),
                )
        if result is None:
            result = self._verify_stateful_authenticated_readiness(realization)
        if result is None:
            result = self._realize_accounts_step(realization) or LabResult(
                success=True,
                message="Lab realized",
            )
        return result

    def _await_realized_service_health(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Wait for the declared services to actually come up.

        ``compose up -d`` only proves the containers were *created*. A resource
        counts as realized only once the backend has started and observed it
        (ADR-046 runtime addendum), so the realization does not return success
        until every realized container is running and every container carrying a
        healthcheck reports healthy.
        """

        containers = [
            node.container_name for node in realization.nodes if node.container_name
        ]
        return wait_for_realized_health(self, containers)

    def _realize_accounts_step(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Realize account placements post-start; fail closed on a backend timeout.

        Returns ``None`` on success (or nothing to realize). Account readiness
        and verification failures already arrive as a fail-closed
        :class:`LabResult`; a mid-mutation ``BackendTimeoutError`` from
        ``container_exec`` is converted into the same bounded envelope here.
        """

        try:
            return self.realize_accounts(realization.accounts, realization.nodes)
        except BackendTimeoutError as exc:
            return LabResult(
                success=False,
                error=f"Account realization timed out: {exc}",
            )
