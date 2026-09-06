"""Secret-safe generated-artifact environment delivery."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path

from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentRealizationSpec,
)

CORTEX_SERVICE_CREDENTIALS_PROFILE = "techvault:cortex-service-credentials/v1"
GENERATED_ARTIFACT_ROOT_RELPATH = Path(".aptl/realization/generated-artifacts")
GENERATED_ENV_ROOT_RELPATH = Path(".aptl/realization/env/generated")

_ENVIRONMENT_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_CORTEX_OUTPUTS = {
    "initializer-api-key": "cortex/initializer-api-key",
    "connector-api-key": "cortex/connector-api-key",
}


def cortex_credentials_root(
    scenario_root: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> Path:
    """Return the contained owner-only root for one Cortex credential artifact."""

    return _canonical_generated_path(
        scenario_root,
        GENERATED_ARTIFACT_ROOT_RELPATH / artifact.name,
    )


def realize_cortex_service_credentials(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
) -> str | None:
    """Generate or reuse the two declared Cortex API keys.

    Returns a bounded, secret-free error string on failure.  Existing valid
    values are retained for the artifact's ``reuse_valid`` lifecycle.
    """

    if not _cortex_contract_valid(artifact):
        return "Cortex credential artifact has an unsupported output contract."
    try:
        root = cortex_credentials_root(scenario_root, artifact)
        _ensure_secure_dir(root)
        observed: set[str] = set()
        for output in artifact.outputs:
            path = _canonical_generated_path(
                scenario_root,
                GENERATED_ARTIFACT_ROOT_RELPATH / artifact.name / output.path,
            )
            _ensure_secure_dir(path.parent)
            value = _read_environment_scalar(path) if path.is_file() else None
            if value is None or value in observed:
                value = _new_distinct_value(observed)
                _atomic_write_secure(path, f"{value}\n")
                os.chmod(path, 0o600)
            observed.add(value)
        return None
    except (OSError, ValueError):
        return "Cortex credential materialization failed."


def materialize_generated_environment_files(
    realization: DeploymentRealizationSpec,
    scenario_root: Path,
) -> tuple[dict[str, Path], str | None]:
    """Project selected generated outputs into owner-only Docker env files."""

    bindings: dict[str, dict[str, str]] = {}
    try:
        for artifact in realization.generated_artifacts:
            if not artifact.environment_consumers:
                continue
            root = _artifact_root(scenario_root, artifact)
            outputs = {output.name: output for output in artifact.outputs}
            for consumer in artifact.environment_consumers:
                output = outputs.get(consumer.output_name)
                if output is None or output.disposition == "producer_private":
                    return (
                        {},
                        "Generated environment binding selects an invalid output.",
                    )
                if (
                    _ENVIRONMENT_VARIABLE.fullmatch(consumer.environment_variable)
                    is None
                ):
                    return (
                        {},
                        "Generated environment binding has an invalid variable name.",
                    )
                path = root / output.path
                value = _read_environment_scalar(path)
                if value is None:
                    return (
                        {},
                        "Generated environment binding has no valid output value.",
                    )
                node_bindings = bindings.setdefault(consumer.target_address, {})
                if consumer.environment_variable in node_bindings:
                    return (
                        {},
                        "Generated environment bindings contain a destination conflict.",
                    )
                node_bindings[consumer.environment_variable] = value

        paths: dict[str, Path] = {}
        for target_address, values in bindings.items():
            path = generated_environment_file(scenario_root, target_address)
            _ensure_secure_dir(path.parent)
            content = "".join(f"{name}={values[name]}\n" for name in sorted(values))
            _atomic_write_secure(path, content)
            os.chmod(path, 0o600)
            paths[target_address] = path
        return paths, None
    except (OSError, ValueError):
        return {}, "Generated environment delivery failed."


def generated_environment_file(scenario_root: Path, target_address: str) -> Path:
    """Return a stable, contained env-file path without embedding authored names."""

    digest = hashlib.sha256(target_address.encode("utf-8")).hexdigest()[:24]
    return _canonical_generated_path(
        scenario_root,
        GENERATED_ENV_ROOT_RELPATH / f"{digest}.env",
    )


def _artifact_root(
    scenario_root: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> Path:
    """Resolve the generated source root for an environment-delivered artifact."""

    if artifact.provenance == CORTEX_SERVICE_CREDENTIALS_PROFILE:
        return cortex_credentials_root(scenario_root, artifact)
    raise ValueError("unsupported generated environment artifact")


def _cortex_contract_valid(artifact: DeploymentGeneratedArtifactRealization) -> bool:
    """Return whether the artifact exactly matches APTL's implemented producer."""

    return bool(
        artifact.provenance == CORTEX_SERVICE_CREDENTIALS_PROFILE
        and artifact.generator == "rendered_config"
        and artifact.lifecycle == "reuse_valid"
        and {
            output.name: output.path
            for output in artifact.outputs
            if output.sensitivity == "secret"
            and output.disposition == "consumer_selected"
        }
        == _CORTEX_OUTPUTS
        and len(artifact.outputs) == len(_CORTEX_OUTPUTS)
    )


def _read_environment_scalar(path: Path) -> str | None:
    """Read a non-empty, single-line env-file-safe scalar without reporting it."""

    try:
        value = path.read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        return None
    return (
        value
        if value and "\n" not in value and "\r" not in value and "\0" not in value
        else None
    )


def _new_distinct_value(observed: set[str]) -> str:
    """Return a cryptographically random value distinct within this artifact."""

    value = secrets.token_urlsafe(32)
    while value in observed:
        value = secrets.token_urlsafe(32)
    return value
