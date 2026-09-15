"""Bind backend and guest observations to one exact RAES apply operation."""

from __future__ import annotations

from collections.abc import Mapping

from raes_contracts.planning import ProvisioningPlan
from raes_contracts.realization_envelope import (
    BackendRealizationEnvelopeModel,
    ObservationStrength,
    RealizationConcern,
)
from raes_contracts.realization_observation import (
    RealizationObservation,
    RealizationObservationDisclosure,
    bind_compute_substrate_observations,
    bind_operating_system_observations,
)
from raes_contracts.realization_observation_demand import (
    compute_substrate_collection_addresses,
)
from raes_contracts.vocabulary import RealizationVerificationScope
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._raes_observation_helpers import ObservedResource

_GUEST_RUNTIME_CONCERNS = frozenset(
    {
        "runtime-dependency-manifests",
        "runtime-filesystem-inventory",
        "runtime-local-identity",
        "runtime-packages",
        "runtime-service-manager-units",
    }
)


def operational_realization_observations(
    *,
    plan: ProvisioningPlan,
    observations: Mapping[str, ObservedResource],
    envelope: BackendRealizationEnvelopeModel,
    previous: tuple[RealizationObservationDisclosure, ...] = (),
) -> tuple[RealizationObservationDisclosure, ...]:
    """Bind native substrate and guest OS reads to this exact apply operation."""

    if plan.operation_id is None or plan.realization_envelope != envelope.identity:
        return ()
    native = _native_observations(plan, observations, envelope)
    substrate = bind_compute_substrate_observations(
        plan=plan,
        observations=native,
        envelope=envelope,
        previous=previous,
        selected_addresses=set(compute_substrate_collection_addresses(plan=plan)),
    )
    bound = bind_operating_system_observations(
        plan=plan,
        observations=native,
        envelope=envelope,
        previous=substrate,
    )
    return _bind_guest_runtime_observations(
        plan=plan,
        observations=observations,
        previous=bound,
    )


def _native_observations(
    plan: ProvisioningPlan,
    observations: Mapping[str, ObservedResource],
    envelope: BackendRealizationEnvelopeModel,
) -> tuple[RealizationObservation, ...]:
    """Project substrate and operating-system reads into native observations."""

    constraint_paths = {
        item.address: item.field_path
        for item in plan.realization_constraints
        if item.concern == "compute-substrate"
    }
    native: list[RealizationObservation] = []
    for sequence, (address, observed) in enumerate(sorted(observations.items())):
        if not observed.realized:
            continue
        substrate = _substrate_observation(
            plan, envelope, constraint_paths, address, sequence
        )
        if substrate is not None:
            native.append(substrate)
        operating_system = _operating_system_observation(
            plan, envelope, address, observed, sequence
        )
        if operating_system is not None:
            native.append(operating_system)
    return tuple(native)


def _substrate_observation(
    plan: ProvisioningPlan,
    envelope: BackendRealizationEnvelopeModel,
    constraint_paths: Mapping[str, str],
    address: str,
    sequence: int,
) -> RealizationObservation | None:
    """Build one daemon-observed substrate result when it was constrained."""

    field_path = constraint_paths.get(address)
    if field_path is None or plan.operation_id is None:
        return None
    return RealizationObservation(
        address=address,
        field_path=field_path,
        concern=RealizationConcern.COMPUTE_SUBSTRATE,
        source=ObservationStrength.DAEMON_OBSERVED,
        value="operating-system-container",
        operation_id=plan.operation_id,
        envelope_digest=envelope.digest,
        configuration_digest=envelope.configuration.configuration_digest,
        observer_version="aptl-docker-inspect/v1",
        sequence=sequence * 2,
        binding_verified=True,
    )


def _operating_system_observation(
    plan: ProvisioningPlan,
    envelope: BackendRealizationEnvelopeModel,
    address: str,
    observed: ObservedResource,
    sequence: int,
) -> RealizationObservation | None:
    """Build one guest-observed OS result when the guest read succeeded."""

    if observed.operating_system is None or plan.operation_id is None:
        return None
    return RealizationObservation(
        address=address,
        field_path=f"{address.removeprefix('provision.node.')}.os",
        concern=RealizationConcern.OPERATING_SYSTEM,
        source=ObservationStrength.GUEST_OBSERVED,
        value=observed.operating_system,
        operation_id=plan.operation_id,
        envelope_digest=envelope.digest,
        configuration_digest=envelope.configuration.configuration_digest,
        observer_version="aptl-container-os-release/v1",
        sequence=sequence * 2 + 1,
        binding_verified=True,
    )


def _bind_guest_runtime_observations(
    *,
    plan: ProvisioningPlan,
    observations: Mapping[str, ObservedResource],
    previous: tuple[RealizationObservationDisclosure, ...],
) -> tuple[RealizationObservationDisclosure, ...]:
    """Disclose only runtime concerns actually read back from the guest."""

    authorities = tuple(
        authority
        for authority in plan.realization_authority
        if authority.requirement_kind in _GUEST_RUNTIME_CONCERNS
    )
    replaced = {
        (
            authority.address,
            authority.field_path,
            authority.domain,
            authority.requirement_kind,
        )
        for authority in authorities
    }
    retained = tuple(
        item
        for item in previous
        if (
            item.address,
            item.field_path,
            item.domain,
            item.requirement_kind,
        )
        not in replaced
    )
    disclosed = []
    for authority in authorities:
        observed = observations.get(authority.address)
        path = CONCERN_PAYLOAD_PATH[authority.requirement_kind]
        if observed is not None and path in observed.concerns:
            disclosed.append(
                RealizationObservationDisclosure(
                    address=authority.address,
                    field_path=authority.field_path,
                    domain=authority.domain,
                    requirement_kind=authority.requirement_kind,
                    verification_scope=RealizationVerificationScope.CONFIGURATION,
                    observation_strength=ObservationStrength.GUEST_OBSERVED,
                )
            )
    return (*retained, *disclosed)


__all__ = ("operational_realization_observations",)
