"""Ordering, environment delivery, and certificate checks for artifacts."""

from __future__ import annotations

from pathlib import Path

from aptl.core.certs import CertResult
from aptl.core.deployment._compose_stateful_constants import CERTIFICATE_PROVENANCE
from aptl.core.deployment._compose_stateful_model import (
    artifact_environment_file_path,
    artifact_source_path,
)
from aptl.core.deployment._realization_primitives import (
    EnvironmentDeliveryRefused,
    environment_file_line,
)
from aptl.core.deployment._stateful_certificates import validate_certificate_bundle
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    valid_environment_variable_name,
)
from aptl.core.lab_types import LabResult
from aptl.utils.pathsafe import (
    PathContainmentError,
    read_contained_nofollow,
    replace_private_nofollow,
)


def artifacts_in_dependency_order(
    artifacts: tuple[DeploymentGeneratedArtifactRealization, ...],
) -> tuple[DeploymentGeneratedArtifactRealization, ...]:
    """Order artifacts after dependencies while preserving deterministic ties."""

    remaining = {artifact.address: artifact for artifact in artifacts}
    dependencies = {
        address: {
            resolved
            for reference in artifact.ordering_dependencies
            if (resolved := _resolve_ordering_reference(reference, remaining))
        }
        for address, artifact in remaining.items()
    }
    ordered: list[DeploymentGeneratedArtifactRealization] = []
    produced: set[str] = set()
    while remaining:
        ready = sorted(
            address
            for address, needs in dependencies.items()
            if address in remaining and needs <= produced
        )
        if not ready:
            ordered.extend(remaining[address] for address in sorted(remaining))
            break
        for address in ready:
            ordered.append(remaining.pop(address))
            produced.add(address)
    return tuple(ordered)


def _resolve_ordering_reference(
    reference: str, artifacts: dict[str, DeploymentGeneratedArtifactRealization]
) -> str | None:
    """Resolve an exact address or the SDL-style generated-artifact name."""

    if reference in artifacts:
        return reference
    name = reference.rsplit(".", 1)[-1]
    matches = [
        address for address, artifact in artifacts.items() if artifact.name == name
    ]
    return matches[0] if len(matches) == 1 else None


def read_generated_output(scenario_root: Path, source: Path) -> str:
    """Read one generated output as an exact environment value.

    The read walks from the resolved scenario root without following links,
    so a symlink planted at an output path is refused instead of read. Only
    the one line feed a generator appends is dropped; anything else, such as
    padding, is kept for the env-file line to carry or refuse (#966).
    """

    root = scenario_root.resolve()
    try:
        data = read_contained_nofollow(root, source.relative_to(root).as_posix())
    except (PathContainmentError, ValueError) as exc:
        raise ValueError("generated output is missing or unsafe") from exc
    value = data.decode("utf-8").removesuffix("\n")
    if not value:
        raise ValueError("empty generated environment value")
    return value


def artifact_environment_bindings(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
    excluded_targets: frozenset[str] = frozenset(),
) -> dict[str, list[tuple[str, Path]]]:
    """Validate and group exact generated-output environment bindings.

    ``excluded_targets`` are consumers that are not Compose services. A
    base-container consumer receives its values through Docker's env file
    instead, so no Compose env file is written for it.
    """

    root = artifact_source_path(scenario_root, artifact)
    outputs = {output.name: root / output.path for output in artifact.outputs}
    by_service: dict[str, list[tuple[str, Path]]] = {}
    for consumer in artifact.environment_consumers:
        if consumer.target_address in excluded_targets:
            continue
        if not valid_environment_variable_name(consumer.environment_variable):
            raise ValueError("invalid generated environment variable")
        source = outputs.get(consumer.output_name)
        if source is None:
            raise ValueError("missing declared generated output")
        by_service.setdefault(consumer.service_name, []).append(
            (consumer.environment_variable, source)
        )
    return by_service


def write_artifact_environment_files(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
    by_service: dict[str, list[tuple[str, Path]]],
) -> None:
    """Write validated output bindings as exact, owner-only Compose env files.

    Every service's file is built and its values checked first, so a value
    refusal leaves the whole set as it was. Each file is then replaced whole
    through the no-follow private writer: a symlinked or non-regular target is
    refused and an existing file's mode never carries over (#966). A target
    refused that way stops the loop, but files replaced before it keep their
    new contents.
    """

    root = scenario_root.resolve()
    payloads = {
        service_name: "".join(
            environment_file_line(
                variable, read_generated_output(root, source), compose=True
            )
            for variable, source in sorted(bindings)
        ).encode()
        for service_name, bindings in by_service.items()
    }
    for service_name, payload in payloads.items():
        target = artifact_environment_file_path(scenario_root, artifact, service_name)
        try:
            replace_private_nofollow(root, target.relative_to(root).as_posix(), payload)
        except PathContainmentError as exc:
            raise EnvironmentDeliveryRefused(
                f"refusing unsafe generated environment file ({exc.reason})"
            ) from exc


def base_container_environment_bindings(
    bindings_by_address: dict[str, dict[str, str]],
    artifact: object,
    consumers: list[object],
    realization_root: Path,
) -> LabResult | None:
    """Resolve admitted generated outputs for generic-container env delivery.

    Outputs are read without following links, and each value is checked now
    against the same Docker env-file rules its writer applies, so a value the
    env file cannot carry fails before the node is materialized (#966).
    """

    source_root = artifact_source_path(realization_root, artifact)
    outputs = {output.name: source_root / output.path for output in artifact.outputs}
    try:
        for consumer in consumers:
            output = outputs.get(consumer.output_name)
            if output is None:
                raise ValueError("missing generated output")
            value = read_generated_output(realization_root, output)
            environment_file_line(consumer.environment_variable, value)
            node_bindings = bindings_by_address.setdefault(consumer.target_address, {})
            if consumer.environment_variable in node_bindings:
                raise ValueError("duplicate generated environment target")
            node_bindings[consumer.environment_variable] = value
    except (OSError, ValueError) as exc:
        reason = f": {exc}" if isinstance(exc, EnvironmentDeliveryRefused) else "."
        return LabResult(
            success=False,
            error=f"Generated artifact {artifact.address} environment delivery failed{reason}",
        )
    return None


def certificate_bundle_failure(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
    result: CertResult,
) -> LabResult | None:
    """Return the first failure in a generated certificate bundle, or none."""

    failure: LabResult | None = None
    if not result.success:
        failure = LabResult(
            success=False,
            error="Certificate artifact generation failed.",
        )
    elif any(
        not (result.certs_dir / output.path).is_file() for output in artifact.outputs
    ):
        failure = LabResult(
            success=False,
            error=f"Generated artifact {artifact.address} is missing declared output.",
        )
    elif artifact.provenance == CERTIFICATE_PROVENANCE:
        errors = validate_certificate_bundle(
            result.certs_dir,
            artifact.outputs,
            scenario_root / artifact.provenance,
        )
        if errors:
            failure = LabResult(success=False, error=errors[0])
    return failure


__all__ = (
    "artifact_environment_bindings",
    "base_container_environment_bindings",
    "artifacts_in_dependency_order",
    "certificate_bundle_failure",
    "read_generated_output",
    "write_artifact_environment_files",
)
