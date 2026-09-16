"""Post-start realization reconciliation (issue #875).

Split out of ``_compose_realization.py`` (module-length budget): everything that
happens after ``compose up`` returns. ``compose up -d`` only proves the
containers were *created*, so a resource counts as realized only once the
backend has started and observed it (ADR-046 runtime addendum): networks are
reconciled, service health is awaited, authenticated readiness is verified, and
only then are accounts realized.
"""

from __future__ import annotations

from aptl.core.deployment._compose_service_health import (
    runtime_expects_completion,
    wait_for_realized_health,
)
from aptl.core.deployment._compose_runtime_observation import (
    ComposeRuntimeOrchestrationObservationMixin,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.deployment.observation import DeploymentObservationContext
from aptl.core.lab_types import LabResult
from aptl.core.deployment._forwarding_agent_realization import (
    realize_forwarding_agents,
)


class ComposeRealizationPostStartMixin(ComposeRuntimeOrchestrationObservationMixin):
    """Reconcile, observe and finish a realization after Compose startup."""

    def _realization_result(
        self,
        start_result: LabResult,
        realization: DeploymentRealizationSpec,
        observation_context: DeploymentObservationContext,
    ) -> LabResult:
        """Return the final result after start, network, health, and accounts.

        Ordering is load-bearing: networks are reconciled, then services must be
        observed healthy, then accounts are realized. Account realization execs
        into the running node containers (``container_exec``), so it cannot run
        until those containers are up and healthy — the health wait gates it.
        """

        if not start_result.success:
            return start_result
        return self._post_start_result(realization, observation_context)

    def _post_start_result(
        self,
        realization: DeploymentRealizationSpec,
        observation_context: DeploymentObservationContext,
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
            forwarding_failures = realize_forwarding_agents(self, realization.nodes)
            if forwarding_failures:
                result = LabResult(
                    success=False,
                    error="; ".join(forwarding_failures[:5]),
                )
        if result is None:
            result = self._verify_stateful_authenticated_readiness(realization)
        if result is None:
            result = self._verify_runtime_orchestration(realization)
        if result is None:
            result = self._realize_accounts_step(realization)
        if result is None:
            retirement_failures = self._retire_completed_autoremove_nodes(
                realization,
                observation_context,
            )
            if retirement_failures:
                result = LabResult(
                    success=False,
                    error="; ".join(retirement_failures[:5]),
                )
        return result or LabResult(success=True, message="Lab realized")

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

        completed = [
            node.container_name
            for node in realization.nodes
            if node.container_name and runtime_expects_completion(node.runtime)
        ]
        ongoing = [
            node.container_name
            for node in realization.nodes
            if node.container_name and not runtime_expects_completion(node.runtime)
        ]
        return wait_for_realized_health(
            self,
            ongoing,
            completed_container_names=completed,
        )

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
