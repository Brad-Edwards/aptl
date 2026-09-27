"""Declared-network reconciliation for image-free Compose realizations."""

from typing import Protocol

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult


class _NetworkReconciler(Protocol):
    """Backend surface that realizes one declared network topology."""

    def _reconcile_realization_networks(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Return bounded reconciliation failures."""

        ...


def reconcile_image_free_networks(
    backend: _NetworkReconciler,
    realization: DeploymentRealizationSpec,
) -> LabResult | None:
    """Bind declared topology after image-free package materialization."""

    if not realization.networks:
        return None
    failures = backend._reconcile_realization_networks(realization)
    if not failures:
        return None
    return LabResult(success=False, error="; ".join(failures[:5]))
