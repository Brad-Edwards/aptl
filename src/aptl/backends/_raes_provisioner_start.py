"""Starting a lowered deployment and reporting what it actually realized.

Two halves of one apply: start the deployment and verify every added observer,
then read the realized world back until its native evidence settles. The
readback loop exists because application-owned inventories settle after
Compose's health gate — a bounded retry, never an admission that an absent or
partial value is good enough.

Split out of ``raes_provisioner`` so the plan-validation half and the
start-and-observe half each stay inside a file a reader can hold in their head.
"""

from __future__ import annotations

import time
from dataclasses import replace

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import ProvisioningPlan
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot
from raes_processor.planner import realization_authority_disclosure

from aptl.backends._raes_apply_reporting import (
    bounded_apply_details as _bounded_apply_details,
    capture_apparatus_observations,
)
from aptl.backends._raes_provisioning_helpers import (
    retryable_readback_gaps as _retryable_readback_gaps,
)
from aptl.backends.raes_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    realized_changed_addresses,
    snapshot_after_apply,
)
from aptl.backends.raes_manifest import (
    create_aptl_manifest,
    create_aptl_realization_envelope,
)
from aptl.backends.raes_observation import (
    observation_evidence,
    observe_realization,
    operational_realization_observations,
)
from aptl.backends.raes_realization import AptlRealization
from aptl.core.deployment._operator_access_proof import operator_access_details
from aptl.core.deployment.observation import DeploymentObservationContext
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.utils.logging import get_logger

log = get_logger("raes-provisioner")

# Application-owned inventories can settle after Compose's health gate. Retry
# bounded native readback without admitting an absent or partial value.
_REALIZATION_READBACK_TIMEOUT_SECONDS = 300.0
_REALIZATION_READBACK_INTERVAL_SECONDS = 2.0


class ProvisionerStartMixin(object):
    """Start the lowered deployment, then report the world it realized."""

    def _start_and_observe_apparatus(
        self,
        deployment_spec: DeploymentRealizationSpec,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        selected_profiles: list[str],
        realization: AptlRealization,
    ) -> (
        tuple[DeploymentObservationContext, tuple[dict[str, object], ...]] | ApplyResult
    ):
        """Start the lowered deployment and verify every added observer."""

        observation_context = DeploymentObservationContext(attempt_id=self._attempt_id)
        result: ApplyResult | None = None
        try:
            start_result = self.deployment_backend.realize(
                deployment_spec,
                scenario_root=self.bundle.root,
                substrate_digests=self._availability_substrate_digests(),
                observation_context=observation_context,
            )
        # The RAES backend-call boundary replaces a TypeError or ValueError
        # escaping apply() with an opaque contract diagnostic. Deployment
        # lowering uses those exception types for invalid realized service
        # models, so preserve the actionable, redacted reason in the failed
        # ApplyResult just as _lowered_spec does above.
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.backend-start-failed",
                    PROVISIONING_ADDRESS,
                    str(exc),
                )
            )
            result = self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )
            start_result = None
        if result is None and start_result is not None and not start_result.success:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.backend-start-failed",
                    PROVISIONING_ADDRESS,
                    start_result.error or "APTL deployment backend failed.",
                )
            )
            result = self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )
        apparatus_observations = (
            capture_apparatus_observations(self.deployment_backend, deployment_spec)
            if result is None
            else None
        )
        if result is None and apparatus_observations is None:
            diagnostics.append(
                diagnostic(
                    "aptl.capture-apparatus.realization-unverified",
                    PROVISIONING_ADDRESS,
                    "Required capture apparatus could not be verified after realization.",
                )
            )
            result = self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )
        return result or (observation_context, apparatus_observations or ())

    def _successful_apply(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        realization: AptlRealization,
        observation_context: DeploymentObservationContext,
        apparatus_observations: tuple[dict[str, object], ...],
    ) -> ApplyResult:
        """Observe and report one deployment whose start checks succeeded."""

        selected_profiles = self.selected_profiles(realization)
        realization_envelope = create_aptl_realization_envelope()
        deadline = time.monotonic() + _REALIZATION_READBACK_TIMEOUT_SECONDS
        attempts = 0
        while True:
            attempts += 1
            # The snapshot must record what the backend realized, not what the
            # plan asked for: the SEM-218 gate reads the realized value out of
            # it, so echoing the plan back would make the gate compare the plan
            # against itself and pass unconditionally (issue #578).
            observations = observe_realization(
                self.deployment_backend,
                realization,
                plan,
                scenario_root=self.bundle.root,
                observation_context=observation_context,
            )
            realized_snapshot = self._with_artifact_satisfactions(
                plan,
                snapshot_after_apply(plan, snapshot, observations),
                realization,
                observation_context,
            )
            realized_snapshot = replace(
                realized_snapshot,
                realization_envelope=realization_envelope.identity,
            )
            operational_observations = operational_realization_observations(
                plan=plan,
                observations=observations,
                envelope=realization_envelope,
                previous=realized_snapshot.realization_observations,
            )
            validation_snapshot = replace(
                realized_snapshot,
                realization_observations=(
                    *realized_snapshot.realization_observations,
                    *operational_observations,
                ),
            )
            readback_diagnostics, _ = realization_authority_disclosure(
                plan,
                validation_snapshot,
                manifest=create_aptl_manifest(),
            )
            if not readback_diagnostics or not _retryable_readback_gaps(
                plan, validation_snapshot, readback_diagnostics
            ):
                break
            now = time.monotonic()
            if now >= deadline:
                log.warning(
                    "Realization readback deadline expired with %d unsettled native evidence records",
                    len(readback_diagnostics),
                )
                break
            if attempts == 1:
                log.info(
                    "Waiting for %d native realization evidence records to settle",
                    len(readback_diagnostics),
                )
            time.sleep(min(_REALIZATION_READBACK_INTERVAL_SECONDS, deadline - now))
        return ApplyResult(
            success=True,
            snapshot=realized_snapshot,
            diagnostics=diagnostics,
            changed_addresses=realized_changed_addresses(plan, realized_snapshot),
            details=_bounded_apply_details(
                {
                    "profiles": selected_profiles,
                    "realization": realization.details(),
                    "observation_evidence": observation_evidence(observations),
                    "observability": {
                        "enabled": self.observability_scope.enabled,
                        "reason": self.observability_scope.reason,
                        "governing_scopes": list(
                            self.observability_scope.governing_scopes
                        ),
                    },
                    "capture_apparatus": list(apparatus_observations),
                    "operator_access": operator_access_details(
                        self.operator_access.accesses
                    ),
                },
                realization,
            ),
            operational_realization_observations=operational_observations,
        )
