"""Docker Compose realization orchestration for typed deployment specs."""

from __future__ import annotations

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
            network_failures = self._ensure_realization_networks(realization)
            result = (
                LabResult(success=False, error="; ".join(network_failures[:5]))
                if network_failures
                else None
            )
        if result is None:
            start_result = self._start_realized_services(
                profiles,
                build=build,
                compose_files=compose_files,
            )
            result = self._realization_result(start_result, realization)
        return result

    def _realization_result(
        self,
        start_result: LabResult,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Return the final result after service start and network reconciliation."""

        result = start_result
        if start_result.success:
            failures = self._reconcile_realization_networks(realization)
            result = (
                LabResult(success=False, error="; ".join(failures[:5]))
                if failures
                else LabResult(success=True, message="Lab realized")
            )
        return result
