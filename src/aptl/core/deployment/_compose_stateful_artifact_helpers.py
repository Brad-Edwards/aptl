"""Ordering, environment delivery, and certificate checks for artifacts."""

from __future__ import annotations

from pathlib import Path

from aptl.core.certs import CertResult
from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)
from aptl.core.deployment._compose_stateful_constants import CERTIFICATE_PROVENANCE
from aptl.core.deployment._compose_stateful_model import (
    artifact_environment_file_path,
    artifact_source_path,
)
from aptl.core.deployment._stateful_certificates import validate_certificate_bundle
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    valid_environment_variable_name,
)
from aptl.core.lab_types import LabResult


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


def artifact_environment_bindings(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
) -> dict[str, list[tuple[str, Path]]]:
    """Validate and group exact generated-output environment bindings."""

    root = artifact_source_path(scenario_root, artifact)
    outputs = {output.name: root / output.path for output in artifact.outputs}
    by_service: dict[str, list[tuple[str, Path]]] = {}
    for consumer in artifact.environment_consumers:
        if not valid_environment_variable_name(consumer.environment_variable):
            raise ValueError("invalid generated environment variable")
        source = outputs.get(consumer.output_name)
        if source is None or not source.is_file():
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
    """Write validated output bindings as owner-only Compose env files."""

    for service_name, bindings in by_service.items():
        target = artifact_environment_file_path(scenario_root, artifact, service_name)
        relative = target.relative_to(scenario_root.resolve())
        target = _canonical_generated_path(scenario_root, relative)
        _ensure_secure_dir(target.parent)
        lines = []
        for variable, source in sorted(bindings):
            value = source.read_text(encoding="utf-8").strip()
            if not value or "\n" in value or "\r" in value:
                raise ValueError("invalid generated environment value")
            lines.append(f"{variable}={value}")
        _atomic_write_secure(target, "\n".join(lines) + "\n")
        target.chmod(0o600)


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
    "artifacts_in_dependency_order",
    "certificate_bundle_failure",
    "write_artifact_environment_files",
)
