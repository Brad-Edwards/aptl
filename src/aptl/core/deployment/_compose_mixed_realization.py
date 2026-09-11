"""Mixed and legacy Compose realization pipeline."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

from aptl.core.deployment._compose_image_free_realization import (
    _image_free_node_addresses,
    _image_free_service_names,
    _strip_image_free_published_ports,
)
from aptl.core.deployment._compose_node_generation import STATIC_COMPOSE_FILENAME
from aptl.core.deployment._compose_runtime_orchestration import (
    realization_has_docker_authority,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult


class ComposeMixedRealizationMixin:
    """Run the ordered Compose pipeline for image-backed and mixed graphs."""

    def _realize_mixed_or_legacy(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool,
        scenario_root: Path,
    ) -> LabResult:
        """Realize a spec with at least one still-Compose-managed node."""

        failure, realization, excluded_services = self._prepare_mixed_subset(
            realization,
            scenario_root,
        )
        if failure is not None:
            return failure
        return self._run_compose_pipeline(
            realization,
            build=build,
            scenario_root=scenario_root,
            excluded_services=excluded_services,
        )

    def _prepare_mixed_subset(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> tuple[LabResult | None, DeploymentRealizationSpec, tuple[str, ...]]:
        """Materialize image-free nodes and return the remaining Compose graph."""

        addresses = _image_free_node_addresses(realization)
        if not addresses:
            return None, realization, ()
        failure = self._materialize_image_free_nodes(
            realization,
            addresses,
            scenario_root,
            self._project_dir,
        )
        if failure is not None:
            return failure, realization, ()
        excluded_services = (
            _image_free_service_names(realization, addresses)
            if (scenario_root / STATIC_COMPOSE_FILENAME).exists()
            else ()
        )
        legacy_content = tuple(
            item for item in realization.content if item.target_address not in addresses
        )
        remaining = cast(
            DeploymentRealizationSpec,
            replace(realization, content=legacy_content),
        )
        remaining = _strip_image_free_published_ports(remaining, addresses)
        return None, remaining, excluded_services

    def _run_compose_pipeline(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool,
        scenario_root: Path,
        excluded_services: tuple[str, ...],
    ) -> LabResult:
        """Run each ordered Compose stage and return the first failure."""

        profiles = list(realization.profiles)
        realization_root = self.realization_root
        failure, compose_files = self._prepare_compose_pipeline(
            realization,
            scenario_root=scenario_root,
            realization_root=realization_root,
        )
        if failure is None:
            compose_files = self._realization_compose_files(
                compose_files,
                realization,
                scenario_root,
                realization_root,
            )
            failure = self._validate_realization_compose_model(
                profiles,
                compose_files,
                realization,
                scenario_root,
                realization_root,
            )
        if failure is None:
            failure = self._start_compose_realization(
                realization,
                profiles=profiles,
                build=build,
                compose_files=compose_files,
                excluded_services=excluded_services,
                scenario_root=scenario_root,
            )
        return failure or LabResult(success=True)

    def _prepare_compose_pipeline(
        self,
        realization: DeploymentRealizationSpec,
        *,
        scenario_root: Path,
        realization_root: Path,
    ) -> tuple[LabResult | None, tuple[Path, ...] | None]:
        """Run ordered prerequisites through authored content realization."""

        compose_files: tuple[Path, ...] | None = None
        failure = self._validate_stateful_realization(realization)
        if failure is None:
            failure = self._validate_stateful_compose_capability(realization)
        if failure is None:
            failure = self._realize_stateful_prerequisites(
                realization,
                realization_root,
            )
        if failure is None:
            failure = self._prepare_spawn_images(realization)
        if failure is None:
            failure, compose_files = self._prepare_realization_images(
                realization,
                scenario_root,
                realization_root,
            )
        if failure is None:
            failure = self._realize_published_ports(realization)
        if failure is None:
            failure = self._realize_networks_and_boundaries(realization)
        if failure is None:
            failure = self._realize_content(realization, scenario_root)
        return failure, compose_files

    def _start_compose_realization(
        self,
        realization: DeploymentRealizationSpec,
        *,
        profiles: list[str],
        build: bool,
        compose_files: tuple[Path, ...] | None,
        excluded_services: tuple[str, ...],
        scenario_root: Path,
    ) -> LabResult:
        """Run phased startup and post-start reconciliation."""

        failure: LabResult | None = None
        if realization_has_docker_authority(realization):
            endpoint = self.revalidate_local_docker_socket()
            failure = None if endpoint.success else endpoint
        if failure is None:
            phase = self._materialize_service_index_schemas(
                realization,
                build=build and not self._offline_staged,
                compose_files=compose_files,
                exclude_services=excluded_services,
                scenario_root=scenario_root,
            )
            failure = phase if phase is not None and not phase.success else None
        if failure is None:
            start_result = self._start_realized_services(
                profiles,
                build=build and not self._offline_staged,
                compose_files=compose_files,
                exclude_services=excluded_services,
                scenario_root=scenario_root,
            )
            failure = self._realization_result(start_result, realization)
        return failure
