"""Docker Compose realization orchestration for typed deployment specs."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from aptl.core.deployment._compose_account_realization import (
    ComposeRealizationAccountMixin,
)
from aptl.core.deployment._compose_content_realization import (
    CONTENT_SEEDER_IMAGE,
    ComposeRealizationContentMixin,
)
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
    "_network_name_candidates",
    "_resolve_realization_networks",
]

_COMPOSE_MODEL_VALIDATION_ERROR = "Generated Compose model validation failed."


class ComposeRealizationMixin(
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
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose."""

        if realization.image_free:
            return self._realize_image_free(realization)

        image_free_addresses = _image_free_node_addresses(realization)
        if image_free_addresses:
            # Mixed realization (ADR-048): materialize the runtime:-declared
            # subset directly first - it never becomes a Compose container -
            # then run the legacy pipeline for the rest, with those service
            # names excluded from `compose up` so neither side starts, skips,
            # or double-realizes the other's nodes.
            node_result = self._materialize_image_free_nodes(
                realization, image_free_addresses
            )
            if node_result is not None:
                return node_result
            excluded_services = _image_free_service_names(realization, image_free_addresses)
            legacy_content = tuple(
                item
                for item in realization.content
                if item.target_address not in image_free_addresses
            )
            realization = replace(realization, content=legacy_content)
            realization = _strip_image_free_published_ports(realization, image_free_addresses)
        else:
            excluded_services = ()

        profiles = list(realization.profiles)
        compose_files: tuple[Path, ...] | None = None

        def _images() -> LabResult | None:
            """Pull/build declared images and capture the resulting compose override."""

            nonlocal compose_files
            result, compose_files = self._prepare_realization_images(realization)
            return result

        def _networks() -> LabResult | None:
            """Ensure declared networks exist, or fail closed on the first error."""

            network_failures = self._ensure_realization_networks(realization)
            if network_failures:
                return LabResult(success=False, error="; ".join(network_failures[:5]))
            return None

        def _compose_model() -> LabResult | None:
            """Render and validate the generated Compose model."""

            nonlocal compose_files
            compose_files = self._realization_compose_files(compose_files, realization)
            return self._validate_realization_compose_model(profiles, compose_files, realization)

        def _start() -> LabResult:
            """Start the realized services and return the final realization result."""

            start_result = self._start_realized_services(
                profiles,
                build=build,
                compose_files=compose_files,
                exclude_services=excluded_services,
            )
            return self._realization_result(start_result, realization)

        # Each step realizes one stage and returns a fail-closed LabResult, or
        # None to fall through to the next stage. The last stage always
        # returns, so the pipeline always ends in a concrete result.
        steps = (
            lambda: self._validate_stateful_realization(realization),
            lambda: self._validate_stateful_compose_capability(realization),
            lambda: self._realize_stateful_prerequisites(realization),
            _images,
            lambda: self._realize_published_ports(realization),
            _networks,
            lambda: self._realize_content(realization),
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
        nodes = tuple(n for n in realization.nodes if n.address in addresses)
        content = tuple(
            item for item in realization.content if item.target_address in addresses
        )
        return _realize_node_subset(self, nodes, content)

    def _realize_image_free(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Realize every node by materializing declared state onto a generic
        base substrate, with no appliance image and no compose-up (ADR-048).

        Networks first, then each node's declared packages/identity/services are
        materialized and verified by read-after-write, then content placements.
        Fails closed on the first unrealized node so a partial range never
        reports success.
        """

        network_failures = self._ensure_realization_networks(realization)
        if network_failures:
            return LabResult(success=False, error="; ".join(network_failures[:5]))
        node_result = _realize_node_subset(self, realization.nodes, realization.content)
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
    ) -> tuple[Path, ...] | None:
        """Add generated realization overrides to the Compose file set."""

        port_override = write_port_override(self._project_dir, realization)
        stateful_override = self._write_stateful_realization_override(realization)
        overrides = tuple(
            path for path in (port_override, stateful_override) if path is not None
        )
        if not overrides:
            return compose_files
        base_files = compose_files or (self._project_dir / "docker-compose.yml",)
        return (*base_files, *overrides)

    def _realize_content(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Materialize typed content placements; fail closed on any seed error.

        Returns ``None`` on success (or when there is nothing to realize) so
        the caller's ``result is None`` chain continues to the next step,
        matching the existing image/network step shape.
        """

        if not realization.content:
            return None
        try:
            self.realize_content(realization.content, seeder_image=CONTENT_SEEDER_IMAGE)
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
    ) -> LabResult | None:
        """Render and inspect the effective generated model before startup."""

        if compose_files is None:
            return None
        command = self._build_command(
            "config",
            profiles,
            compose_files=compose_files,
        )
        stateful = bool(
            realization.generated_artifacts or realization.persistent_volumes
        )
        error = (
            self._effective_compose_model_error(command, realization)
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
            self._project_dir,
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
    return replace(realization, nodes=legacy_nodes)


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
