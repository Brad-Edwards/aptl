"""APTL ACES runtime target.

This module is the handoff layer between the external ACES SDL/runtime
packages and APTL's existing deployment primitives.  It intentionally keeps
Docker/SSH details behind ``DeploymentBackend``; the ACES provisioner only
translates a provisioning plan into the compose profiles APTL can already
start.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import ChangeAction, ProvisioningPlan
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot
from aces_runtime.manager import RuntimeManager
from aces_runtime.registry import RuntimeTarget
from aces_sdl import SDLError, parse_sdl_file

from aptl.backends.aces_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    has_error,
    render_aces_diagnostics,
    snapshot_after_apply,
    unsupported_resource_diagnostics,
)
from aptl.backends.aces_manifest import APTL_ACES_TARGET_NAME, create_aptl_manifest
from aptl.backends.aces_profiles import (
    configured_profiles,
    explicit_compose_profile_hints,
    load_compose_profile_index,
    node_aliases,
    select_backend_profiles,
)
from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("aces-backend")

DEFAULT_ACES_SCENARIO = Path("scenarios") / "techvault.sdl.yaml"


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
) -> RuntimeTarget:
    """Build the ACES runtime target for APTL."""

    provisioner = AptlProvisioner(
        project_dir=project_dir,
        config=config,
        deployment_backend=backend,
    )
    return RuntimeTarget(
        name=APTL_ACES_TARGET_NAME,
        manifest=create_aptl_manifest(),  # type: ignore[arg-type]
        provisioner=provisioner,  # type: ignore[arg-type]
    )


def start_aces_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> LabResult:
    """Start an APTL lab by compiling and applying an ACES SDL scenario."""

    resolved_scenario = scenario_path or DEFAULT_ACES_SCENARIO
    if not resolved_scenario.is_absolute():
        resolved_scenario = project_dir / resolved_scenario
    try:
        scenario = parse_sdl_file(resolved_scenario)
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=backend,
        )
        manager = RuntimeManager(target)
        execution_plan = manager.plan(scenario)
        # APTL is a provisioning-only ACES backend: its manifest declares no
        # evaluator or orchestrator (see aces_manifest.AptlBackendManifest). A
        # scenario may still carry evaluation content — notably the `conditions`
        # section, whose entries are Docker Compose healthchecks realized during
        # provisioning, not by an ACES evaluator. The runtime planner flags such
        # content with the evaluation-domain `evaluator.missing` ERROR and marks
        # the whole plan invalid, so RuntimeManager.apply would refuse before any
        # provisioning runs. Allowlist only that one expected diagnostic; stay
        # fail-closed for every other planner error (e.g. provisioning ordering
        # cycles or unsupported provisioning capabilities), which surface on the
        # ExecutionPlan diagnostics rather than necessarily in the
        # ProvisioningPlan that the provisioner re-validates. Then apply only the
        # provisioning phase through APTL's provisioner.
        blocking = [
            diag
            for diag in execution_plan.diagnostics
            if diag.is_error
            and not (diag.domain == "evaluation" and diag.code == "evaluator.missing")
        ]
        if blocking:
            return LabResult(
                success=False,
                error=render_aces_diagnostics(blocking),
            )
        result = target.provisioner.apply(
            execution_plan.provisioning,
            execution_plan.base_snapshot,
        )
    except (FileNotFoundError, SDLError, TypeError, ValueError) as exc:
        return LabResult(
            success=False,
            error=redact(f"ACES runtime handoff failed: {exc}"),
        )

    if result.success:
        return LabResult(
            success=True,
            message=(
                "Lab started through ACES runtime target "
                f"'{APTL_ACES_TARGET_NAME}'"
            ),
        )
    return LabResult(
        success=False,
        error=render_aces_diagnostics(result.diagnostics),
    )


@dataclass
class AptlProvisioner(object):
    """Provisioning-only ACES backend adapter for APTL."""

    project_dir: Path
    config: AptlConfig
    deployment_backend: "DeploymentBackend"

    def validate(self, plan: object) -> list[Diagnostic]:
        """Validate that the ACES provisioning plan is APTL-realizable."""

        if not isinstance(plan, ProvisioningPlan):
            return [
                diagnostic(
                    "aptl.provisioner.invalid-plan",
                    PROVISIONING_ADDRESS,
                    "APTL provisioner expected an ACES ProvisioningPlan.",
                )
            ]

        diagnostics: list[Diagnostic] = []
        diagnostics.extend(unsupported_resource_diagnostics(plan))

        profiles, profile_diagnostics = self._profiles_from_plan(plan)
        diagnostics.extend(profile_diagnostics)
        configured = configured_profiles(self.config)
        if configured and not (set(configured) & set(profiles)):
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.no-configured-profile-matches",
                    PROVISIONING_ADDRESS,
                    (
                        "ACES provisioning plan did not declare any node "
                        "that maps to an enabled APTL compose profile."
                    ),
                )
            )

        return diagnostics

    def apply(self, plan: object, snapshot: object) -> ApplyResult:
        """Apply an ACES provisioning plan via APTL's deployment backend."""

        working_snapshot = (
            snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        )
        diagnostics = self.validate(plan)
        result = ApplyResult(
            success=False,
            snapshot=working_snapshot,
            diagnostics=diagnostics,
        )
        if isinstance(plan, ProvisioningPlan) and not has_error(diagnostics):
            result = self._apply_valid_plan(plan, working_snapshot, diagnostics)
        return result

    def _apply_valid_plan(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
    ) -> ApplyResult:
        """Apply a validated ACES plan to the deployment backend."""
        profiles, profile_diagnostics = self._profiles_from_plan(plan)
        diagnostics.extend(profile_diagnostics)
        if has_error(diagnostics):
            return ApplyResult(
                success=False,
                snapshot=snapshot,
                diagnostics=diagnostics,
            )

        selected_profiles = select_backend_profiles(self.config, profiles)
        start_result = self.deployment_backend.start(selected_profiles)
        if not start_result.success:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.backend-start-failed",
                    PROVISIONING_ADDRESS,
                    start_result.error or "APTL deployment backend failed.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=snapshot,
                diagnostics=diagnostics,
                details={"profiles": selected_profiles},
            )
        return ApplyResult(
            success=True,
            snapshot=snapshot_after_apply(plan, snapshot),
            diagnostics=diagnostics,
            changed_addresses=_changed_addresses(plan),
            details={"profiles": selected_profiles},
        )

    def _profiles_from_plan(
        self,
        plan: ProvisioningPlan,
    ) -> tuple[frozenset[str], list[Diagnostic]]:
        """Resolve APTL Compose profiles from ACES node resources."""
        diagnostics: list[Diagnostic] = []
        try:
            profile_index = load_compose_profile_index(self.project_dir)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            return (
                frozenset(),
                [
                    diagnostic(
                        "aptl.provisioner.compose-profile-index-failed",
                        PROVISIONING_ADDRESS,
                        redact(str(exc)),
                    )
                ],
            )

        profiles: set[str] = set()
        for resource in plan.resources.values():
            if resource.resource_type != "node":
                continue
            payload = resource.payload
            profiles.update(explicit_compose_profile_hints(payload))
            profiles.update(
                profile_index.profiles_for_aliases(
                    node_aliases(resource.address, payload)
                )
            )

        if not profiles:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.profile-resolution-failed",
                    PROVISIONING_ADDRESS,
                    (
                        "ACES provisioning plan contained no node resources "
                        "that map to APTL compose profiles."
                    ),
                )
            )
        return frozenset(profiles), diagnostics


def _changed_addresses(plan: ProvisioningPlan) -> list[str]:
    """Return addresses whose planned operation changes runtime state."""
    return [
        op.address
        for op in plan.operations
        if op.action != ChangeAction.UNCHANGED
    ]
