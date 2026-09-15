"""Provisioning component of APTL's full remote-control-plane RAES target."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import ProvisioningPlan, RuntimeDomain
from raes_contracts.realization_structure import validate_realization_value
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.backends.raes_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    has_error,
    realized_changed_addresses,
    snapshot_after_apply,
)
from aptl.backends.raes_artifact_mechanisms import (
    SOURCE_ARTIFACT_REQUIREMENT_KIND,
    dynamic_composition_provenance_ref,
)
from aptl.backends.raes_artifact_satisfaction import satisfactions_for_plan
from aptl.backends.raes_content_satisfaction import content_satisfactions_for_plan
from aptl.backends.raes_manifest import (
    create_aptl_manifest,
    create_aptl_realization_envelope,
)
from aptl.backends.raes_observability_scope import ObservabilityScopeDecision
from aptl.backends.raes_observation import (
    observation_evidence,
    observe_realization,
    operational_realization_observations,
)
from aptl.backends.raes_realization import (
    AptlRealization,
    interpret_provisioning_plan,
)
from aptl.backends.raes_profiles import (
    load_compose_profile_index,
    select_backend_profiles,
)
from aptl.core.config import AptlConfig
from aptl.core.experiment.capture_plan import CapturePlan, empty_capture_plan
from aptl.core.deployment.realization import (
    DeploymentCaptureApparatus,
    DeploymentRealizationSpec,
)
from aptl.core.deployment.observation import DeploymentObservationContext
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from raes_contracts.contracts import ArtifactAvailabilityContext

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.scenario_bundle import ScenarioBundle


_MAX_APPLY_DETAILS_BYTES = 65_536


def _compact_realization_details(realization: AptlRealization) -> dict[str, object]:
    """Return identities/counts; complete realized state lives in the snapshot."""

    full = realization.details()
    return {
        "profiles": full["profiles"],
        "resource_counts": full["resource_counts"],
        "nodes": [
            {
                "address": node.address,
                "name": node.name,
                "backend_services": list(node.backend_services),
                "container_name": node.container_name,
                "profiles": list(node.profiles),
            }
            for node in realization.nodes
        ],
        "networks": [network.details() for network in realization.networks],
        "placements": [
            {
                "address": placement.address,
                "resource_type": placement.resource_type,
                "target_address": placement.target_address,
            }
            for placement in realization.placements
        ],
        "generated_artifacts": [
            {"address": artifact.address}
            for artifact in realization.generated_artifacts
        ],
        "persistent_volumes": [
            {"address": volume.address} for volume in realization.persistent_volumes
        ],
    }


def _bounded_apply_details(
    details: dict[str, object], realization: AptlRealization
) -> dict[str, object]:
    """Keep RAES ApplyResult details finite without losing observer additions."""

    try:
        serialized_size = len(json.dumps(details, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError):
        serialized_size = _MAX_APPLY_DETAILS_BYTES + 1
    if (
        serialized_size <= _MAX_APPLY_DETAILS_BYTES
        and validate_realization_value(details).conformant
    ):
        return details

    compact = {**details, "realization": _compact_realization_details(realization)}
    evidence = compact.get("observation_evidence")
    if isinstance(evidence, dict):
        compact["observation_evidence"] = {
            "projection": "runtime-snapshot",
            "record_count": len(evidence),
        }
    return compact


@dataclass
class AptlProvisioner(object):
    """Provisioning component of APTL's ``full-remote-control-plane`` target."""

    project_dir: Path
    config: AptlConfig
    deployment_backend: "DeploymentBackend"
    # The scenario being realized, and the root every scenario-declared input is
    # anchored to. Required: realization never falls back to ``project_dir`` (the
    # engine checkout). For an in-tree scenario the bundle root *is* the project
    # directory, which is what keeps an unmoved scenario unchanged (issue #874).
    bundle: ScenarioBundle
    # RAES's backend-call boundary replaces a failed apply's diagnostics with
    # its snapshot-contract / SEM-218 gate output (the gate reads the
    # never-realized snapshot, so every exact declaration looks unrealized).
    # Keep the last failed apply's own report here so the handoff can
    # re-attach the actionable failure (issue #677).
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
    _cached_plan: object | None = field(default=None, init=False, repr=False)
    _cached_realization: AptlRealization | None = field(
        default=None, init=False, repr=False
    )

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

        return list(self.realize_plan(plan).diagnostics)

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
        observation_context = DeploymentObservationContext()
        start_result = self.deployment_backend.realize(
            deployment_spec,
            scenario_root=self.bundle.root,
            substrate_digests=self._availability_substrate_digests(),
            observation_context=observation_context,
        )
        if not start_result.success:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.backend-start-failed",
                    PROVISIONING_ADDRESS,
                    start_result.error or "APTL deployment backend failed.",
                )
            )
            return self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )
        apparatus_observations = self._capture_apparatus_observations(deployment_spec)
        if apparatus_observations is None:
            diagnostics.append(
                diagnostic(
                    "aptl.capture-apparatus.realization-unverified",
                    PROVISIONING_ADDRESS,
                    "Required capture apparatus could not be verified after realization.",
                )
            )
            return self._failed_apply(
                snapshot, diagnostics, selected_profiles, realization
            )
        # The snapshot must record what the backend realized, not what the plan
        # asked for: the SEM-218 gate reads the realized value out of it, so
        # echoing the plan back would make the gate compare the plan against
        # itself and pass unconditionally (issue #578).
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
        realized_snapshot = self._with_capture_apparatus_entries(
            realized_snapshot, apparatus_observations
        )
        realization_envelope = create_aptl_realization_envelope()
        realized_snapshot = replace(
            realized_snapshot,
            realization_envelope=realization_envelope.identity,
        )
        operational_observations = operational_realization_observations(
            plan=plan,
            observations=observations,
            envelope=realization_envelope,
            previous=snapshot.realization_observations,
        )
        return ApplyResult(
            success=True,
            snapshot=realized_snapshot,
            diagnostics=diagnostics,
            changed_addresses=[
                *realized_changed_addresses(plan, realized_snapshot),
                *(entry["runtime_address"] for entry in apparatus_observations),
            ],
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
                },
                realization,
            ),
            operational_realization_observations=operational_observations,
        )

    def _capture_apparatus_observations(
        self, deployment_spec: DeploymentRealizationSpec
    ) -> tuple[dict[str, object], ...] | None:
        """Read back the actual added observer set from the deployment owner."""

        if not deployment_spec.capture_apparatus:
            return ()
        observe = getattr(self.deployment_backend, "observe_capture_apparatus", None)
        if not callable(observe):
            return None
        result = observe(deployment_spec)
        if result is None or len(result) != len(deployment_spec.capture_apparatus):
            return None
        return tuple(
            {
                **item,
                "runtime_address": "apparatus.capture.kali-session-capture",
            }
            for item in result
        )

    @staticmethod
    def _with_capture_apparatus_entries(
        snapshot: RuntimeSnapshot,
        observations: tuple[dict[str, object], ...],
    ) -> RuntimeSnapshot:
        """Report every actual observability addition in portable runtime state."""

        if not observations:
            return snapshot
        entries = dict(snapshot.entries)
        for observation in observations:
            address = str(observation["runtime_address"])
            entries[address] = SnapshotEntry(
                address=address,
                domain=RuntimeDomain.PROVISIONING,
                resource_type="capture-apparatus",
                payload=dict(observation),
            )
        return snapshot.with_entries(entries)

    def selected_profiles(self, realization: AptlRealization) -> list[str]:
        """Apply the admitted scope decision to the ordinary backend profiles."""
        return self.observability_scope.select_profiles(
            select_backend_profiles(self.config, realization.profiles)
        )

    def _availability_substrate_digests(self) -> dict[str, str]:
        """Return the address-scoped substrate config id availability verified.

        For each dynamic-composition node the availability pass resolved the
        generic substrate's immutable config id once and recorded it as a
        verified integrity ref paired with the dynamic-composition provenance
        ref. Threading that exact id into realization means the base container
        starts the bytes availability verified, never a second resolution of the
        mutable tag (issue #876 cycle-6 review). Empty when no node authored a
        dynamic-composition source.
        """

        availability = self.artifact_availability
        if availability is None:
            return {}
        provenance = dynamic_composition_provenance_ref()
        digests: dict[str, str] = {}
        for requirement in getattr(availability, "requirements", ()):
            if provenance not in getattr(requirement, "verified_provenance_refs", ()):
                continue
            # A dynamic-composition node authors an open source with no exact or
            # materialized artifact, so its verified integrity set is EXACTLY the
            # one substrate digest. Require that: a multi-valued or empty set is
            # ambiguous, and taking one arbitrarily could start an unrelated
            # artifact, so it yields no verified digest and the start fails closed
            # (issue #876 cycle-7 review).
            refs = getattr(requirement, "verified_integrity_refs", ())
            if len(refs) == 1:
                digests[requirement.address] = refs[0]
        return digests

    def _with_artifact_satisfactions(
        self,
        plan: ProvisioningPlan,
        realized: RuntimeSnapshot,
        realization: AptlRealization,
        observation_context: DeploymentObservationContext,
    ) -> RuntimeSnapshot:
        """Attach artifact satisfaction disclosures to the realized snapshot.

        RAES's runtime non-approximation gate reads ``artifact_satisfaction``
        off each entry to prove the backend realized the artifact the author
        pinned. A node's disclosure is derived from the digest read back off the
        running container; a content placement's is derived from the bytes the
        pack resolved for it (issue #875), because copied content is not an OCI
        image and has no container digest. Either way an address whose artifact
        cannot be established, or whose realized digest differs from the pin,
        simply gets no disclosure and the gate rejects the apply.

        Only addresses the observation pass reported realized have a snapshot
        entry at all, so a disclosure can never outlive the realization it
        describes. A scenario that authors no artifact requirement produces no
        disclosures and the snapshot is returned unchanged.
        """

        container_names = {
            node.address: node.container_name
            for node in realization.nodes
            if node.container_name
        }
        content_by_address = {
            placement.address: placement.content
            for placement in realization.placements
            if placement.content is not None
        }
        manifest = create_aptl_manifest()
        disclosures = {
            **satisfactions_for_plan(
                plan,
                container_names,
                self.deployment_backend,
                manifest,
                requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
                observation_context=observation_context,
            ),
            **content_satisfactions_for_plan(
                plan,
                content_by_address,
                self.bundle.root,
                manifest,
                requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
            ),
        }
        if not disclosures:
            return realized
        entries = dict(realized.entries)
        for address, disclosure in disclosures.items():
            entry = entries.get(address)
            if entry is None:
                continue
            entries[address] = replace(
                entry,
                payload={**entry.payload, "artifact_satisfaction": disclosure},
            )
        return realized.with_entries(entries)

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
        try:
            profile_index = load_compose_profile_index(self.bundle.root)
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
