"""Provisioning component of APTL's full remote-control-plane RAES target."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import ProvisioningPlan
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot

from aptl.backends._raes_apply_reporting import (
    bounded_apply_details as _bounded_apply_details,
    with_artifact_satisfactions,
)

from aptl.backends.raes_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    has_error,
)
from aptl.backends._raes_provisioner_start import ProvisionerStartMixin
from aptl.backends._raes_provisioning_helpers import (
    availability_substrate_digests,
    compose_validity_diagnostics,
)
from aptl.backends.raes_observability_scope import ObservabilityScopeDecision
from aptl.backends.raes_operator_access import OperatorAccessDecision
from aptl.backends.raes_realization import (
    AptlRealization,
    interpret_provisioning_plan,
)
from aptl.backends.raes_profiles import select_backend_profiles
from aptl.core.config import AptlConfig
from aptl.core.experiment.capture_plan import CapturePlan, empty_capture_plan
from aptl.core.deployment.realization import (
    DeploymentCaptureApparatus,
    DeploymentRealizationSpec,
)
from aptl.core.deployment.observation import DeploymentObservationContext
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from raes_contracts.contracts import ArtifactAvailabilityContext

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.scenario_bundle import ScenarioBundle


log = get_logger("raes-provisioner")

# Application-owned inventories can settle after Compose's health gate. Retry
# bounded native readback without admitting an absent or partial value.
_REALIZATION_READBACK_TIMEOUT_SECONDS = 300.0
_REALIZATION_READBACK_INTERVAL_SECONDS = 2.0


@dataclass
class AptlProvisioner(ProvisionerStartMixin):
    """Provisioning component of APTL's ``full-remote-control-plane`` target."""

    project_dir: Path
    config: AptlConfig
    deployment_backend: "DeploymentBackend"
    # The scenario and root anchoring every declared input. Realization never
    # falls back to ``project_dir``; see issue #874.
    bundle: ScenarioBundle
    # RAES's backend-call boundary replaces failed-apply diagnostics with the
    # snapshot gate output. Preserve the actionable report; see issue #677.
    last_failure_diagnostics: tuple[Diagnostic, ...] = ()
    # The trusted availability facts gathered before planning (ADR-051). They
    # carry the address-scoped immutable substrate config id each
    # dynamic-composition node was verified against, so realization starts that
    # exact id rather than resolving the mutable tag a second time at apply
    # (issue #876 cycle-6 review). None for a scenario with no artifact demand.
    artifact_availability: ArtifactAvailabilityContext | None = None
    capture_plan: CapturePlan = field(default_factory=empty_capture_plan)
    observability_scope: ObservabilityScopeDecision = field(
        default_factory=ObservabilityScopeDecision
    )
    # Declared operator interactive access, admitted from the scenario before
    # planning. RAES carries it in the participant model, not the provisioning
    # plan, so it reaches the deployment through here (issue #1006).
    operator_access: OperatorAccessDecision = field(
        default_factory=OperatorAccessDecision
    )
    _cached_plan: object | None = field(default=None, init=False, repr=False)
    _cached_realization: AptlRealization | None = field(
        default=None, init=False, repr=False
    )
    _attempt_id: str | None = field(default=None, init=False, repr=False)

    def bind_attempt_id(self, attempt_id: str | None) -> None:
        """Bind the one already-resolved lab-start attempt to deployment."""

        self._attempt_id = attempt_id

    def validate(self, plan: object) -> list[Diagnostic]:
        """Validate that the RAES provisioning plan is APTL-realizable."""

        if not isinstance(plan, ProvisioningPlan):
            return [
                diagnostic(
                    "aptl.provisioner.invalid-plan",
                    PROVISIONING_ADDRESS,
                    "APTL provisioner expected a RAES ProvisioningPlan.",
                )
            ]

        return [
            *self.realize_plan(plan).diagnostics,
            *self._unrealizable_operator_access_diagnostics(),
        ]

    def _unrealizable_operator_access_diagnostics(self) -> list[Diagnostic]:
        """Refuse declared interactive access this backend cannot make reachable."""

        return [
            diagnostic(
                "aptl.provisioner.operator-access-unrealizable",
                PROVISIONING_ADDRESS,
                (
                    f"Declared interactive access {access.agent}/{access.access_id} "
                    f"({access.channel} to {access.target_node}) has no backend "
                    "apparatus that can make it reachable."
                ),
            )
            for access in self.operator_access.unrealizable
        ]

    def apply(self, plan: object, snapshot: object) -> ApplyResult:
        """Apply a RAES provisioning plan via APTL's deployment backend."""

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
            realization = self.realize_plan(plan)
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
                    details=_bounded_apply_details(
                        {"realization": realization.details()}, realization
                    ),
                )
        self.last_failure_diagnostics = (
            () if result.success else tuple(result.diagnostics)
        )
        return result

    @staticmethod
    def _failed_apply(
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        selected_profiles: list[str],
        realization: AptlRealization,
    ) -> ApplyResult:
        """Return the one shape every pre-start apply failure reports."""

        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=diagnostics,
            details=_bounded_apply_details(
                {
                    "profiles": selected_profiles,
                    "realization": realization.details(),
                },
                realization,
            ),
        )

    def _lowered_spec(
        self,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        selected_profiles: list[str],
        realization: AptlRealization,
    ) -> tuple[DeploymentRealizationSpec | None, ApplyResult | None]:
        """Return the lowered deployment spec, or the failure preventing one."""

        validity_diagnostics = self._compose_validity_diagnostics(selected_profiles)
        if validity_diagnostics:
            diagnostics.extend(validity_diagnostics)
            return None, self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )
        try:
            return realization.deployment_spec(
                selected_profiles,
                capture_apparatus=tuple(
                    DeploymentCaptureApparatus(
                        apparatus_id=item.apparatus_id,
                        service_name=item.service_name,
                        container_name=item.container_name,
                        target_refs=item.target_refs,
                        governing_scopes=item.governing_scopes,
                        environment_visible=item.environment_visible,
                        observer_effects=item.observer_effects,
                    )
                    for item in self.capture_plan.apparatus
                ),
            ), None
        # Lowering reports an unrealizable graph by raising with a stable code
        # in the message. RAES's backend-call boundary turns any ValueError or
        # TypeError out of apply into the fixed text "Backend could not
        # construct a valid apply result" and drops the message, so raising here
        # loses the code, the address and the node. The contract is a failed
        # ApplyResult carrying diagnostics; return one.
        except (TypeError, ValueError) as exc:
            log.exception("Deployment backend realization rejected its lowered model")
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.realization-not-lowerable",
                    PROVISIONING_ADDRESS,
                    str(exc),
                )
            )
            return None, self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )

    def _apply_valid_plan(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        realization: AptlRealization,
    ) -> ApplyResult:
        """Apply a validated RAES plan to the deployment backend."""
        selected_profiles = self.selected_profiles(realization)
        deployment_spec, failure = self._lowered_spec(
            snapshot, diagnostics, selected_profiles, realization
        )
        if failure is not None:
            return failure
        started = self._start_and_observe_apparatus(
            deployment_spec,
            snapshot,
            diagnostics,
            selected_profiles,
            realization,
        )
        if isinstance(started, ApplyResult):
            return started
        observation_context, apparatus_observations = started

        return self._successful_apply(
            plan,
            snapshot,
            diagnostics,
            realization,
            observation_context,
            apparatus_observations,
        )

    def selected_profiles(self, realization: AptlRealization) -> list[str]:
        """Apply the admitted scope decision to the ordinary backend profiles."""
        return self.observability_scope.select_profiles(
            select_backend_profiles(self.config, realization.profiles)
        )

    def _availability_substrate_digests(self) -> dict[str, str]:
        """Return address-scoped immutable substrate ids verified by availability."""

        return availability_substrate_digests(self.artifact_availability)

    def _with_artifact_satisfactions(
        self,
        plan: ProvisioningPlan,
        realized: RuntimeSnapshot,
        realization: AptlRealization,
        observation_context: DeploymentObservationContext,
    ) -> RuntimeSnapshot:
        """Attach artifact disclosures derived from realized state."""

        return with_artifact_satisfactions(
            plan,
            realized,
            realization,
            observation_context,
            self.deployment_backend,
            self.bundle.root,
        )

    def _compose_validity_diagnostics(
        self, selected_profiles: list[str]
    ) -> list[Diagnostic]:
        """Refuse to start when the selected profiles form an invalid project.

        ``deployment_backend.start`` boots with ``docker compose --profile
        <selected>``, which activates every service in each selected profile,
        not just the declared RAES nodes. If an activated service depends on a
        service the selection excludes, Compose rejects the project at ``up``
        time. Catch that here so ``aptl lab start`` fails fast with an APTL
        diagnostic instead of a raw Compose "undefined service" error.
        """
        return compose_validity_diagnostics(self.bundle.root, selected_profiles)

    def realize_plan(self, plan: ProvisioningPlan) -> AptlRealization:
        """Interpret one plan once, reusing its exact serving interaction."""

        if plan is self._cached_plan and self._cached_realization is not None:
            return self._cached_realization
        realization = interpret_provisioning_plan(
            plan=plan,
            config=self.config,
            bundle=self.bundle,
            component_root=self.project_dir,
        )
        self._cached_plan = plan
        self._cached_realization = realization
        return realization

    def _realize_plan(self, plan: ProvisioningPlan) -> AptlRealization:
        """Backward-compatible private route to the cached interpreter."""
        return self.realize_plan(plan)

    @staticmethod
    def _invalid_plan_diagnostics(plan: object) -> list[Diagnostic]:
        if isinstance(plan, ProvisioningPlan):
            return []
        return [
            diagnostic(
                "aptl.provisioner.invalid-plan",
                PROVISIONING_ADDRESS,
                "APTL provisioner expected a RAES ProvisioningPlan.",
            )
        ]
