"""Provisioning component of APTL's full remote-control-plane ACES target."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import ProvisioningPlan
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot

from aptl.backends.aces_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    has_error,
    realized_changed_addresses,
    snapshot_after_apply,
)
from aptl.backends.aces_observation import observation_evidence, observe_realization
from aptl.backends.aces_realization import (
    AptlRealization,
    interpret_provisioning_plan,
)
from aptl.backends.aces_profiles import (
    load_compose_profile_index,
    select_backend_profiles,
)
from aptl.core.config import AptlConfig
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend


@dataclass
class AptlProvisioner(object):
    """Provisioning component of APTL's ``full-remote-control-plane`` target."""

    project_dir: Path
    config: AptlConfig
    deployment_backend: "DeploymentBackend"
    # ACES's backend-call boundary replaces a failed apply's diagnostics with
    # its snapshot-contract / SEM-218 gate output (the gate reads the
    # never-realized snapshot, so every exact declaration looks unrealized).
    # Keep the last failed apply's own report here so the handoff can
    # re-attach the actionable failure (issue #677).
    last_failure_diagnostics: tuple[Diagnostic, ...] = ()

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

        return list(self._realize_plan(plan).diagnostics)

    def apply(self, plan: object, snapshot: object) -> ApplyResult:
        """Apply an ACES provisioning plan via APTL's deployment backend."""

        working_snapshot = (
            snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        )
        diagnostics = self._invalid_plan_diagnostics(plan)
        result = ApplyResult(
            success=False,
            snapshot=working_snapshot,
            diagnostics=diagnostics,
        )
        if isinstance(plan, ProvisioningPlan):
            realization = self._realize_plan(plan)
            diagnostics = list(realization.diagnostics)
            if not has_error(diagnostics):
                result = self._apply_valid_plan(
                    plan,
                    working_snapshot,
                    diagnostics,
                    realization,
                )
            else:
                result = ApplyResult(
                    success=False,
                    snapshot=working_snapshot,
                    diagnostics=diagnostics,
                    details={"realization": realization.details()},
                )
        self.last_failure_diagnostics = (
            () if result.success else tuple(result.diagnostics)
        )
        return result

    def _apply_valid_plan(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        realization: AptlRealization,
    ) -> ApplyResult:
        """Apply a validated ACES plan to the deployment backend."""
        selected_profiles = select_backend_profiles(self.config, realization.profiles)
        validity_diagnostics = self._compose_validity_diagnostics(selected_profiles)
        if validity_diagnostics:
            diagnostics.extend(validity_diagnostics)
            return ApplyResult(
                success=False,
                snapshot=snapshot,
                diagnostics=diagnostics,
                details={
                    "profiles": selected_profiles,
                    "realization": realization.details(),
                },
            )
        deployment_spec = realization.deployment_spec(selected_profiles)
        start_result = self.deployment_backend.realize(deployment_spec)
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
                details={
                    "profiles": selected_profiles,
                    "realization": realization.details(),
                },
            )
        # The snapshot must record what the backend realized, not what the plan
        # asked for: the SEM-218 gate reads the realized value out of it, so
        # echoing the plan back would make the gate compare the plan against
        # itself and pass unconditionally (issue #578).
        observations = observe_realization(
            self.deployment_backend,
            realization,
            plan,
        )
        realized_snapshot = snapshot_after_apply(plan, snapshot, observations)
        return ApplyResult(
            success=True,
            snapshot=realized_snapshot,
            diagnostics=diagnostics,
            changed_addresses=realized_changed_addresses(plan, realized_snapshot),
            details={
                "profiles": selected_profiles,
                "realization": realization.details(),
                "observation_evidence": observation_evidence(observations),
            },
        )

    def _compose_validity_diagnostics(
        self, selected_profiles: list[str]
    ) -> list[Diagnostic]:
        """Refuse to start when the selected profiles form an invalid project.

        ``deployment_backend.start`` boots with ``docker compose --profile
        <selected>``, which activates every service in each selected profile,
        not just the declared ACES nodes. If an activated service depends on a
        service the selection excludes, Compose rejects the project at ``up``
        time. Catch that here so ``aptl lab start`` fails fast with an APTL
        diagnostic instead of a raw Compose "undefined service" error.
        """
        try:
            profile_index = load_compose_profile_index(self.project_dir)
        except (OSError, ValueError) as exc:
            return [
                diagnostic(
                    "aptl.provisioner.compose-profile-index-failed",
                    PROVISIONING_ADDRESS,
                    redact(str(exc)),
                )
            ]
        gaps = profile_index.cross_profile_dependency_gaps(set(selected_profiles))
        return [
            diagnostic(
                "aptl.provisioner.compose-project-invalid",
                PROVISIONING_ADDRESS,
                (
                    "Selected APTL compose profiles form an invalid project: "
                    f"service '{service_name}' depends on "
                    f"{', '.join(dependencies)}, which the profile selection "
                    "excludes. Declare the dependency's node or enable its "
                    "profile."
                ),
            )
            for service_name, dependencies in sorted(gaps.items())
        ]

    def _realize_plan(self, plan: ProvisioningPlan) -> AptlRealization:
        """Interpret an ACES plan against APTL's supported contract."""
        return interpret_provisioning_plan(
            plan=plan,
            project_dir=self.project_dir,
            config=self.config,
        )

    @staticmethod
    def _invalid_plan_diagnostics(plan: object) -> list[Diagnostic]:
        if isinstance(plan, ProvisioningPlan):
            return []
        return [
            diagnostic(
                "aptl.provisioner.invalid-plan",
                PROVISIONING_ADDRESS,
                "APTL provisioner expected an ACES ProvisioningPlan.",
            )
        ]
