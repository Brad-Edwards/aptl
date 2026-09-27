"""Canonical immutable capture plan shared by SDL and experiment admission."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import rfc8785
from raes_processor.capture_admission import (
    CaptureDemand,
    capture_admission_diagnostics,
)

from aptl.core.experiment.capture_registry import (
    DEFAULT_COLLECTOR_REGISTRY,
    CaptureBinding,
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistry,
)
from aptl.core.experiment.errors import AdmissionRejection, diagnostic

_CAPTURE_PLAN_SCHEMA = "aptl-capture-plan/v1"


@dataclass(frozen=True)
class CaptureApparatus:
    """One minimum-intrusion observer added to the realized environment.

    Unlike native readback, an apparatus item changes the scenario's in-principle
    visible world.  It is therefore admitted against the authored realization
    scope and carried in the immutable plan so deployment and runtime reporting
    cannot silently add, remove, or rename it after admission.
    """

    apparatus_id: str
    service_name: str
    container_name: str
    purpose: str
    target_refs: tuple[str, ...]
    governing_scopes: tuple[str, ...]
    environment_visible: bool
    observer_effects: tuple[str, ...]

    def projection(self) -> dict[str, object]:
        return {
            "apparatus_id": self.apparatus_id,
            "service_name": self.service_name,
            "container_name": self.container_name,
            "purpose": self.purpose,
            "target_refs": list(self.target_refs),
            "governing_scopes": list(self.governing_scopes),
            "environment_visible": self.environment_visible,
            "observer_effects": list(self.observer_effects),
        }


@dataclass(frozen=True)
class AdmittedCaptureDemand:
    """One public RAES demand pinned to one trusted collector declaration."""

    demand: CaptureDemand
    registration_id: str
    implementation_version: str
    contract_version: str
    effective_config_digest: str
    visibility_class: CaptureVisibility
    limits: CaptureLimits
    selected_output_contract: str

    def projection(self) -> dict[str, object]:
        return {
            "demand": {
                key: list(value) if isinstance(value, tuple) else value
                for key, value in self.demand.__dict__.items()
            },
            "registration_id": self.registration_id,
            "implementation_version": self.implementation_version,
            "contract_version": self.contract_version,
            "effective_config_digest": self.effective_config_digest,
            "visibility_class": self.visibility_class.value,
            "selected_output_contract": self.selected_output_contract,
            "limits": {
                "max_bytes": self.limits.max_bytes,
                "max_artifact_count": self.limits.max_artifact_count,
                "max_duration_s": self.limits.max_duration_s,
            },
        }

    def runtime_binding(self, capture_plan_id: str) -> CaptureBinding:
        """Project this admitted SDL demand onto the incumbent coordinator binding."""

        demand = self.demand
        return CaptureBinding(
            capture_spec_id=capture_plan_id,
            requirement_id=demand.demand_id,
            window_refs=demand.window_kinds,
            registration_id=self.registration_id,
            implementation_version=self.implementation_version,
            contract_version=self.contract_version,
            effective_config_digest=self.effective_config_digest,
            channel_ref_id=(
                demand.channel_refs[0]
                if demand.channel_refs
                else demand.channel_kinds[0]
            ),
            channel_ref_version=None,
            channel_kind=demand.channel_kinds[0],
            capture_kind=demand.capture_kind,
            capture_scope="scenario",
            output_contract=self.selected_output_contract,
            expected_media_types=demand.media_types,
            required_artifact_roles=demand.artifact_roles,
            sensitivity=demand.sensitivity,
            redaction_required=demand.redaction_policy is not None,
            integrity_requirements=demand.integrity_modes,
            retention_policy=(
                demand.retention_policy_refs[0]
                if demand.retention_policy_refs
                else None
            ),
            loss_disclosure_required=True,
            visibility_class=self.visibility_class,
            limits=self.limits,
            redaction_policy=demand.redaction_policy,
        )


@dataclass(frozen=True)
class CapturePlan:
    """Complete deterministic capture authority for one scenario snapshot."""

    source_identity: str
    bindings: tuple[AdmittedCaptureDemand, ...]
    apparatus: tuple[CaptureApparatus, ...]
    canonical_bytes: bytes
    plan_digest: str
    plan_id: str

    def runtime_bindings(self) -> tuple[CaptureBinding, ...]:
        return tuple(binding.runtime_binding(self.plan_id) for binding in self.bindings)


def admit_capture_demands(
    demands: tuple[CaptureDemand, ...],
    *,
    source_identity: str,
    apparatus: tuple[CaptureApparatus, ...] = (),
    registry: CollectorRegistry = DEFAULT_COLLECTOR_REGISTRY,
) -> CapturePlan:
    """Admit every public demand atomically and return canonical plan bytes."""

    admitted: list[AdmittedCaptureDemand] = []
    diagnostics = []
    observation = registry.observation_projection()
    for demand in sorted(demands, key=lambda item: (item.address, item.demand_id)):
        registration = registry.match_demand(demand)
        if registration is None:
            diagnostics.extend(capture_admission_diagnostics((demand,), observation))
            continue
        offer = registration.capture_offer
        if offer is None or not offer.output_contract:
            diagnostics.append(
                diagnostic(
                    "aptl.capture-admission.output-contract-unavailable",
                    demand.address,
                    "The selected collector does not declare a persistable output contract.",
                )
            )
            continue
        admitted.append(
            AdmittedCaptureDemand(
                demand=demand,
                registration_id=registration.registration_id,
                implementation_version=registration.implementation_version,
                contract_version=registration.contract_version,
                effective_config_digest=registration.effective_config_digest(),
                visibility_class=registration.visibility_class,
                limits=registration.limits,
                selected_output_contract=offer.output_contract,
            )
        )
    if diagnostics:
        raise AdmissionRejection(tuple(diagnostics))

    projection = {
        "schema_version": _CAPTURE_PLAN_SCHEMA,
        "source_identity": source_identity,
        "bindings": [binding.projection() for binding in admitted],
        "apparatus": [item.projection() for item in apparatus],
    }
    canonical = rfc8785.dumps(projection)
    digest = hashlib.sha256(canonical).hexdigest()
    return CapturePlan(
        source_identity=source_identity,
        bindings=tuple(admitted),
        apparatus=apparatus,
        canonical_bytes=canonical,
        plan_digest=f"sha256:{digest}",
        plan_id=f"capture-plan-{digest}",
    )


def empty_capture_plan() -> CapturePlan:
    """Return the canonical capture plan for a scenario with no obligations."""

    return admit_capture_demands((), source_identity="none")
