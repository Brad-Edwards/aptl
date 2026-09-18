"""Read-only runtime qualification for Compose deployment backends."""

from __future__ import annotations

import json
from pathlib import Path

from aptl.core.deployment._compose_node_generation import (
    STATIC_COMPOSE_FILENAME,
    render_realization_compose,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    effective_orchestration_model_errors,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.deployment.runtime_materialization import (
    SHARED_DOCKER_PROFILE,
    RuntimeMaterializationIssue,
    RuntimeMaterializationProfile,
    effective_runtime_contract_issues,
    qualify_runtime_materialization,
)
from aptl.core.lab_types import LabResult


def _issues_failure(
    issues: tuple[RuntimeMaterializationIssue, ...],
) -> LabResult | None:
    """Project bounded qualification issues into a deployment result."""

    return (
        LabResult(
            success=False,
            error="; ".join(issue.render() for issue in issues[:5]),
        )
        if issues
        else None
    )


class ComposeRuntimeMaterializationMixin:
    """Qualify runtime authority before ownership or Docker mutation."""

    def qualify_runtime_materialization(
        self,
        realization: DeploymentRealizationSpec,
        *,
        scenario_root: Path,
    ) -> LabResult:
        """Expose the read-only graph gate to pre-build scenario admission."""

        failure = self._runtime_materialization_preflight(
            realization,
            scenario_root=scenario_root,
        )
        return failure or LabResult(success=True)

    @staticmethod
    def _runtime_materialization_profile(
        realization: DeploymentRealizationSpec,
    ) -> RuntimeMaterializationProfile:
        """Return the backend envelope proven before deployment mutation."""

        del realization
        return SHARED_DOCKER_PROFILE

    def _runtime_materialization_preflight(
        self,
        realization: DeploymentRealizationSpec,
        *,
        scenario_root: Path | None = None,
    ) -> LabResult | None:
        """Qualify the complete runtime graph without creating backend state."""

        target_qualification = getattr(
            self,
            "_qualify_runtime_materialization_target",
            None,
        )
        failure = (
            target_qualification() if target_qualification is not None else None
        )
        profile = self._runtime_materialization_profile(realization)
        if failure is None:
            issues = qualify_runtime_materialization(
                realization,
                profile=profile,
                policy=self._runtime_authority_policy,
            )
            failure = _issues_failure(issues)
        if failure is None:
            failure = self._rendered_runtime_contract_failure(realization, profile)
        if failure is None and scenario_root is not None:
            failure = self._static_runtime_contract_preflight(
                realization,
                scenario_root=scenario_root,
                profile=profile,
            )
        return failure

    @staticmethod
    def _rendered_runtime_contract_failure(
        realization: DeploymentRealizationSpec,
        profile: RuntimeMaterializationProfile,
    ) -> LabResult | None:
        """Exercise pure image-backed lowering before mixed dispatch."""

        try:
            rendered = render_realization_compose(realization)
        except ValueError as exc:
            return LabResult(
                success=False,
                error=(
                    "aptl.provisioner.runtime-materialization-unsupported: "
                    f"backend={profile.name} limitation={exc}"
                ),
            )
        issues = effective_runtime_contract_issues(
            rendered,
            realization,
            profile=profile,
        )
        return _issues_failure(issues)

    @staticmethod
    def _needs_static_runtime_check(
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> bool:
        """Whether a static Compose model participates in this realization."""

        static = scenario_root / STATIC_COMPOSE_FILENAME
        image_addresses = {image.address for image in realization.images}
        has_image_service = any(
            node.address in image_addresses and node.service_name
            for node in realization.nodes
        )
        return static.exists() and has_image_service

    def _render_static_runtime_model(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
        profile: RuntimeMaterializationProfile,
    ) -> tuple[object | None, LabResult | None]:
        """Render the static effective model without interpolation."""

        static = scenario_root / STATIC_COMPOSE_FILENAME
        command = self._build_command(
            "config",
            list(realization.profiles),
            compose_files=(static,),
            scenario_root=scenario_root,
        )
        command.extend(["--no-interpolate", "--format", "json"])
        result = self._run(command)
        failure = None
        payload: object | None = None
        if result.returncode != 0:
            failure = LabResult(
                success=False,
                error=(
                    "aptl.provisioner.runtime-materialization-unsupported: "
                    f"backend={profile.name} limitation=effective Compose model is unavailable"
                ),
            )
        else:
            try:
                payload = json.loads(result.stdout)
            except (TypeError, ValueError):
                payload = None
        return payload, failure

    @staticmethod
    def _static_contract_failure(
        payload: object,
        realization: DeploymentRealizationSpec,
        profile: RuntimeMaterializationProfile,
    ) -> LabResult | None:
        """Project effective runtime and orchestration mismatches."""

        issues = effective_runtime_contract_issues(
            payload,
            realization,
            profile=profile,
        )
        errors = [issue.render() for issue in issues[:5]]
        authority_errors = effective_orchestration_model_errors(payload, realization)
        if authority_errors and len(errors) < 5:
            node = (
                realization.docker_authority_admissions[0].node_address
                if realization.docker_authority_admissions
                else "provision.graph"
            )
            errors.append(
                "aptl.provisioner.runtime-materialization-unsupported: "
                f"node={node} field=runtime.orchestration_authorities "
                f"backend={profile.name} limitation={authority_errors[0]}"
            )
        return LabResult(success=False, error="; ".join(errors)) if errors else None

    def _static_runtime_contract_preflight(
        self,
        realization: DeploymentRealizationSpec,
        *,
        scenario_root: Path,
        profile: RuntimeMaterializationProfile,
    ) -> LabResult | None:
        """Read and compare a static effective model before mixed mutation."""

        if not self._needs_static_runtime_check(realization, scenario_root):
            return None
        payload, failure = self._render_static_runtime_model(
            realization,
            scenario_root,
            profile,
        )
        return failure or self._static_contract_failure(
            payload,
            realization,
            profile,
        )
