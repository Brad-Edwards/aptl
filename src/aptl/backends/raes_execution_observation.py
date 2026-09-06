"""Bind native substrate and guest-OS readback to one RAES plan execution."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from dataclasses import replace

from raes_contracts.apparatus import RealizationVerificationScope
from raes_contracts.planning import ProvisioningPlan
from raes_contracts.realization_envelope import (
    ObservationStrength,
    RealizationConcern,
)
from raes_contracts.realization_observation import (
    ObservedOperatingSystemIdentity,
    RealizationObservation,
    bind_compute_substrate_observations,
    bind_operating_system_observations,
    compute_substrate_readback_addresses,
)
from raes_contracts.runtime_state import (
    RealizationObservationDisclosure,
    RuntimeSnapshot,
)

from aptl.backends._raes_observation_helpers import ObservedResource
from aptl.backends.raes_realization_model import AptlRealization

_OBSERVER_VERSION = "aptl-container-realization-observer/1"
_DISTRIBUTIONS = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "rocky": "rocky-linux",
    "rhel": "red-hat-enterprise-linux",
    "alpine": "x-aptl:alpine",
    "almalinux": "x-aptl:almalinux",
    "amzn": "x-aptl:amazon-linux",
}


def bind_execution_observations(
    backend: object,
    realization: AptlRealization,
    plan: ProvisioningPlan,
    snapshot: RuntimeSnapshot,
    observations: Mapping[str, ObservedResource],
) -> RuntimeSnapshot:
    """Attach execution-bound compute-substrate and OS disclosures.

    The disclosures are created only after the backend has returned and its
    running containers have been observed.  A missing readback produces no
    disclosure, leaving RAES's non-approximation gate to reject the apply.
    """

    manifest = _matching_manifest(plan)
    if manifest is None:
        return snapshot
    envelope = manifest.realization_envelope
    if envelope is None:
        return snapshot
    previous = snapshot.realization_observations
    native = _native_observations(
        backend,
        realization,
        plan,
        observations,
        envelope.digest,
        envelope.configuration.configuration_digest,
        compute_substrate_readback_addresses(
            plan=plan,
            envelope=envelope,
            previous=previous,
        ),
    )
    disclosures = bind_compute_substrate_observations(
        plan=plan,
        observations=native,
        envelope=envelope,
        previous=previous,
    )
    disclosures = bind_operating_system_observations(
        plan=plan,
        observations=native,
        envelope=envelope,
        previous=disclosures,
    )
    disclosures = (
        *disclosures,
        *_os_family_disclosures(plan, native, disclosures),
    )
    return replace(
        snapshot,
        realization_observations=disclosures,
        realization_envelope=plan.realization_envelope,
    )


def _os_family_disclosures(
    plan: ProvisioningPlan,
    observations: tuple[RealizationObservation, ...],
    previous: tuple[RealizationObservationDisclosure, ...],
) -> tuple[RealizationObservationDisclosure, ...]:
    """Bind the legacy exact OS-family authority to native guest readback."""

    identities = {
        observation.address: observation
        for observation in observations
        if observation.concern == RealizationConcern.OPERATING_SYSTEM
        and isinstance(observation.value, ObservedOperatingSystemIdentity)
    }
    existing = {
        (disclosure.address, disclosure.field_path, disclosure.requirement_kind)
        for disclosure in previous
    }
    disclosures: list[RealizationObservationDisclosure] = []
    for authority in plan.realization_authority:
        key = (authority.address, authority.field_path, authority.requirement_kind)
        observation = identities.get(authority.address)
        if (
            authority.requirement_kind != "os-family"
            or observation is None
            or key in existing
        ):
            continue
        disclosures.append(
            RealizationObservationDisclosure(
                address=authority.address,
                field_path=authority.field_path,
                domain=authority.domain,
                requirement_kind="os-family",
                verification_scope=RealizationVerificationScope.PRESENCE,
                observation_strength=ObservationStrength.GUEST_OBSERVED,
            )
        )
    return tuple(disclosures)


def _matching_manifest(plan: ProvisioningPlan) -> object | None:
    """Return APTL's manifest only when the plan selected its current envelope."""

    from aptl.backends.raes_manifest import create_aptl_manifest

    if plan.operation_id is None or plan.realization_envelope is None:
        return None
    manifest = create_aptl_manifest()
    envelope = manifest.realization_envelope
    return (
        manifest
        if envelope is not None and plan.realization_envelope == envelope.identity
        else None
    )


def _native_observations(
    backend: object,
    realization: AptlRealization,
    plan: ProvisioningPlan,
    observations: Mapping[str, ObservedResource],
    envelope_digest: str,
    configuration_digest: str,
    substrate_addresses: tuple[str, ...],
) -> tuple[RealizationObservation, ...]:
    """Read current container substrate and guest identities."""

    containers = {
        node.address: node.container_name
        for node in realization.nodes
        if node.container_name
    }
    native: list[RealizationObservation] = []
    for sequence, address in enumerate(substrate_addresses):
        observed = observations.get(address)
        if observed is None or not observed.realized or address not in containers:
            continue
        constraint = next(
            (
                item
                for item in plan.realization_constraints
                if item.address == address and item.concern == "compute-substrate"
            ),
            None,
        )
        if constraint is None:
            continue
        native.append(
            RealizationObservation(
                address=address,
                field_path=constraint.field_path,
                concern=RealizationConcern.COMPUTE_SUBSTRATE,
                source=ObservationStrength.DAEMON_OBSERVED,
                value="operating-system-container",
                operation_id=plan.operation_id,
                envelope_digest=envelope_digest,
                configuration_digest=configuration_digest,
                observer_version=_OBSERVER_VERSION,
                sequence=sequence,
                binding_verified=True,
            )
        )
    for sequence, (address, container) in enumerate(sorted(containers.items())):
        observed = observations.get(address)
        if observed is None or not observed.realized:
            continue
        identity = _observe_guest_operating_system(backend, container)
        if identity is None:
            continue
        native.append(
            RealizationObservation(
                address=address,
                field_path=f"nodes.{address.removeprefix('provision.node.')}.operating-system",
                concern=RealizationConcern.OPERATING_SYSTEM,
                source=ObservationStrength.GUEST_OBSERVED,
                value=identity,
                operation_id=plan.operation_id,
                envelope_digest=envelope_digest,
                configuration_digest=configuration_digest,
                observer_version=_OBSERVER_VERSION,
                sequence=sequence,
                binding_verified=True,
            )
        )
    return tuple(native)


def _observe_guest_operating_system(
    backend: object,
    container_name: str,
) -> ObservedOperatingSystemIdentity | None:
    """Read and normalize a running container's guest OS release identity."""

    runner = getattr(backend, "container_exec", None)
    inspector = getattr(backend, "container_inspect", None)
    reader = getattr(backend, "container_os_release", None)
    raw_release = ""
    if callable(runner):
        try:
            result = runner(container_name, ["cat", "/etc/os-release"], timeout=15)
        except (OSError, RuntimeError):
            result = None
        if result is not None and result.returncode == 0:
            raw_release = result.stdout
    # A run-to-completion container cannot be exec'd after its exact zero exit.
    # Read the same public identity file from its retained guest filesystem via
    # the daemon; this remains guest state, not a declaration/image-name echo.
    if not raw_release and callable(reader):
        try:
            raw_release = reader(container_name) or ""
        except (OSError, RuntimeError):
            raw_release = ""
    fields = _os_release_fields(raw_release)
    if fields:
        distribution = _DISTRIBUTIONS.get(fields.get("ID", ""))
        version = fields.get("VERSION_ID", "")
        if distribution and version:
            try:
                return ObservedOperatingSystemIdentity("linux", distribution, version)
            except (TypeError, ValueError):
                return None
    # A distroless image intentionally has no shell or /etc/os-release.  Its
    # running OCI config still identifies the minimal userspace product line and
    # bounded release; this is the only supported no-release-file guest shape.
    if not callable(inspector):
        return None
    info = inspector(container_name)
    labels = _config_labels(info)
    version = labels.get("org.opencontainers.image.version", "")
    if not version or "opentelemetry-collector" not in labels.get(
        "org.opencontainers.image.name", ""
    ):
        return None
    try:
        return ObservedOperatingSystemIdentity("linux", "x-aptl:distroless", version)
    except (TypeError, ValueError):
        return None


def _os_release_fields(raw: object) -> dict[str, str]:
    """Parse the bounded ID/VERSION_ID subset of ``/etc/os-release``."""

    if not isinstance(raw, str) or len(raw) > 16_384:
        return {}
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"ID", "VERSION_ID"}:
            continue
        try:
            tokens = shlex.split(value, posix=True)
        except ValueError:
            return {}
        if len(tokens) != 1:
            return {}
        fields[key] = tokens[0]
    return fields


def _config_labels(info: object) -> dict[str, str]:
    """Return string OCI labels from one daemon-observed container config."""

    config = info.get("Config") if isinstance(info, Mapping) else None
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        return {}
    return {
        str(key): str(value)
        for key, value in labels.items()
        if isinstance(key, str) and isinstance(value, str)
    }


__all__ = ["bind_execution_observations"]
