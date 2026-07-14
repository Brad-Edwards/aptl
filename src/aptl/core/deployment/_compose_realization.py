"""Docker Compose realization orchestration for typed deployment specs."""

from __future__ import annotations

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


class ComposeRealizationMixin(
    ComposeRealizationImageMixin,
    ComposeRealizationNetworkMixin,
    ComposeRealizationContentMixin,
    ComposeRealizationAccountMixin,
):
    """Realize typed scenario specs through Docker Compose."""

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose."""

        profiles = list(realization.profiles)
        image_result, compose_files = self._prepare_realization_images(realization)
        result = image_result
        if result is None:
            result = self._realize_published_ports(realization)
        if result is None:
            network_failures = self._ensure_realization_networks(realization)
            result = (
                LabResult(success=False, error="; ".join(network_failures[:5]))
                if network_failures
                else None
            )
        if result is None:
            result = self._realize_content(realization)
        if result is None:
            start_result = self._start_realized_services(
                profiles,
                build=build,
                compose_files=self._realization_compose_files(
                    compose_files, realization
                ),
            )
            result = self._realization_result(start_result, realization)
        return result

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
        """Add the declared-host-port override to the realization compose files."""

        port_override = write_port_override(self._project_dir, realization)
        if port_override is None:
            return compose_files
        return (*(compose_files or ()), port_override)

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

        network_failures = self._reconcile_realization_networks(realization)
        if network_failures:
            return LabResult(success=False, error="; ".join(network_failures[:5]))
        health_failures = self._await_realized_service_health(realization)
        if health_failures:
            return LabResult(success=False, error="; ".join(health_failures[:5]))
        return self._realize_accounts_step(realization) or LabResult(
            success=True, message="Lab realized"
        )

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
