"""Docker Compose bindings for RAES stateful realization resources."""

from __future__ import annotations

import re
import secrets
import subprocess
from pathlib import Path

import yaml

from aptl.core.certs import CertResult, ensure_ssl_certs
from aptl.core.soc_ca import derive_soc_service_certs, ensure_soc_certs
from aptl.core.credentials import (
    RENDERED_MANAGER_RELPATH,
    _atomic_write_owner_only,
    _atomic_write_secure,
    _canonical_generated_path,
    _enforce_mode,
    _ensure_secure_dir,
    sync_manager_config,
)
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_PROVENANCE,
    CERTIFICATE_ROOT_RELPATH,
    MIN_OVERRIDE_COMPOSE_VERSION,
    SOC_CERT_PROFILE,
    SOC_CERTS_ROOT_RELPATH,
    STATEFUL_OVERRIDE_RELPATH,
    WAZUH_MANAGER_CONFIG_PROVENANCES,
)
from aptl.core.deployment._compose_stateful_graph import (
    compose_version,
    owned_wazuh_services,
    stateful_realization_errors,
)
from aptl.core.deployment._compose_stateful_model import (
    artifact_source_path as _artifact_source_path,
    effective_stateful_model_errors as _effective_stateful_model_errors,
    generated_environment_file_path as _generated_environment_file_path,
    stateful_override_payload,
)
from aptl.core.deployment._compose_stateful_readiness import (
    ComposeStatefulReadinessMixin,
    _load_stateful_env,
)
from aptl.core.deployment._compose_stateful_services import StatefulDumper
from aptl.core.deployment._flag_signing_keys import (
    FLAG_SIGNING_PROFILE_V2,
    realize_flag_signing_keys,
)
from aptl.core.deployment._ssh_key_bundle import realize_ssh_key_bundle
from aptl.core.deployment._stateful_certificates import validate_certificate_bundle
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult

artifact_source_path = _artifact_source_path
effective_stateful_model_errors = _effective_stateful_model_errors
generated_environment_file_path = _generated_environment_file_path

_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_GENERATED_VALUE_LENGTH = 4096
_MAX_ENV_FILE_LENGTH = 65536


class ComposeStatefulRealizationMixin(ComposeStatefulReadinessMixin):
    """Validate and bind typed stateful resources before Compose startup."""

    def _validate_stateful_realization(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Return a failure when the admitted stateful graph is invalid."""

        errors = stateful_realization_errors(
            realization,
            local_artifacts=getattr(self, "supports_local_artifacts", True),
        )
        return LabResult(success=False, error="; ".join(errors[:5])) if errors else None

    def _write_stateful_realization_override(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> Path | None:
        """Persist the stateful Compose override when resources require one.

        The generated override is scenario-local; it is written under
        ``scenario_root`` (the bundle root).
        """

        return write_stateful_override(
            scenario_root,
            self.project_name,
            realization,
        )

    def _validate_stateful_compose_capability(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Require Compose service replacement support before artifact mutation."""

        if not owned_wazuh_services(realization):
            return None
        result = self._run(["docker", "compose", "version", "--short"], timeout=30)
        version = compose_version(result.stdout) if result.returncode == 0 else None
        if version is not None and version >= MIN_OVERRIDE_COMPOSE_VERSION:
            return None
        return LabResult(
            success=False,
            error="Docker Compose 2.24.4 or later is required for stateful service ownership.",
        )

    def _realize_stateful_prerequisites(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> LabResult | None:
        """Materialize and verify every declared generated artifact.

        Generated artifacts land under ``scenario_root`` (the bundle root); the
        operator credential source stays the control-plane ``project_dir/.env``.
        """

        failure: LabResult | None = None
        for artifact in realization.generated_artifacts:
            failure = self._realize_one_generated_artifact(artifact, scenario_root)
            if failure is not None:
                break
        return failure

    def _realize_one_generated_artifact(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Materialize one generated artifact, dispatched by generator kind."""

        realizer = {
            "certificate_bundle": self._realize_certificate_bundle,
            "rendered_config": self._realize_rendered_config,
            "ssh_key_bundle": self._realize_ssh_key_bundle,
        }.get(artifact.generator)
        if realizer is None:
            return LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} has unsupported "
                    f"generator {artifact.generator!r}."
                ),
            )
        failure = realizer(artifact, scenario_root)
        if failure is not None:
            return failure
        return self._realize_generated_environment_consumers(artifact, scenario_root)

    @staticmethod
    def _realize_ssh_key_bundle(
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Generate the declared SSH key bundle under its owner-only staging root.

        The staging root is the artifact's canonical source path; only a
        consumer's selected, non-producer-private outputs are bind-mounted from
        it, so the generated control-plane key never reaches a node.
        """

        staging_root = artifact_source_path(scenario_root, artifact)
        try:
            _canonical_generated_path(
                scenario_root, staging_root.relative_to(scenario_root.resolve())
            )
        except ValueError:
            return LabResult(
                success=False,
                error="SSH key bundle path failed containment validation.",
            )
        error = realize_ssh_key_bundle(artifact, staging_root)
        if error is not None:
            return LabResult(
                success=False,
                error=f"SSH key bundle generation failed: {error}",
            )
        return None

    def _realize_rendered_config(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Render an admitted ``rendered_config`` artifact, dispatched by provenance.

        The rendered config is a scenario-local generated artifact written under
        ``scenario_root``. Two producer profiles are implemented: the wazuh
        cluster manager config (ADR-028; credential from the control-plane
        ``project_dir/.env``) and the per-node flag-signing keys (#875).
        """

        if artifact.provenance == FLAG_SIGNING_PROFILE_V2:
            return self._realize_flag_signing_keys(artifact, scenario_root)
        if artifact.environment_consumers and not artifact.consumers:
            return self._realize_generated_secret_outputs(artifact, scenario_root)

        unsupported_binding = (
            artifact.provenance not in WAZUH_MANAGER_CONFIG_PROVENANCES
            or len(artifact.outputs) != 1
            or artifact.outputs[0].path != RENDERED_MANAGER_RELPATH.name
        )
        failure: LabResult | None = None
        output: Path | None = None
        if unsupported_binding:
            failure = LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} has unsupported "
                    "rendered-config binding."
                ),
            )
        else:
            env, placeholder_input = _load_stateful_env(self._project_dir)
            if placeholder_input:
                failure = LabResult(
                    success=False,
                    error="Rendered config rejected placeholder credential input.",
                )
            elif env is None:
                failure = LabResult(
                    success=False,
                    error="Rendered config materialization failed: ValueError.",
                )
            else:
                try:
                    output = sync_manager_config(
                        scenario_root,
                        env.wazuh_cluster_key,
                    )
                except (OSError, ValueError) as exc:
                    failure = LabResult(
                        success=False,
                        error=(
                            "Rendered config materialization failed: "
                            f"{type(exc).__name__}."
                        ),
                    )
        if failure is None and (output is None or not output.is_file()):
            failure = LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} is missing declared output."
                ),
            )
        return failure

    @staticmethod
    def _realize_generated_secret_outputs(
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Generate opaque values for an environment-only rendered artifact."""

        if any(
            consumer.delivery_mode != "environment"
            for consumer in artifact.environment_consumers
        ):
            return LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} has an unsupported "
                    "generic env-file producer binding."
                ),
            )
        source = artifact_source_path(scenario_root, artifact)
        try:
            source_relative = source.relative_to(scenario_root.resolve())
            _canonical_generated_path(scenario_root, source_relative)
            for output in artifact.outputs:
                target_relative = source_relative / output.path
                target = _canonical_generated_path(scenario_root, target_relative)
                value: str | None = None
                if artifact.lifecycle == "reuse_valid" and target.exists():
                    value = target.read_text(encoding="utf-8")
                    _validate_generated_scalar(value)
                if value is None:
                    value = secrets.token_urlsafe(48)
                _ensure_secure_dir(target.parent)
                target = _canonical_generated_path(scenario_root, target_relative)
                _atomic_write_owner_only(target, value)
        except (OSError, UnicodeError, ValueError):
            return LabResult(
                success=False,
                error="Generated environment artifact failed containment or value validation.",
            )
        return None

    @staticmethod
    def _realize_generated_environment_consumers(
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Create or validate secret-safe host env files for declared consumers."""

        outputs = {output.name: output for output in artifact.outputs}
        source = artifact_source_path(scenario_root, artifact)
        try:
            source_relative = source.relative_to(scenario_root.resolve())
            for consumer in artifact.environment_consumers:
                output = outputs[consumer.output]
                output_relative = source_relative / output.path
                output_path = _canonical_generated_path(scenario_root, output_relative)
                value = output_path.read_text(encoding="utf-8")
                if consumer.delivery_mode == "env_file":
                    _validate_env_file(value)
                    _enforce_mode(output_path, 0o600, "generated env file")
                    continue
                _validate_generated_scalar(value)
                name = consumer.environment_variable or ""
                if _ENVIRONMENT_NAME.fullmatch(name) is None:
                    raise ValueError("invalid environment variable name")
                delivery_path = generated_environment_file_path(
                    scenario_root, artifact, consumer
                )
                delivery_relative = delivery_path.relative_to(scenario_root.resolve())
                delivery_path = _canonical_generated_path(
                    scenario_root, delivery_relative
                )
                _ensure_secure_dir(delivery_path.parent)
                delivery_path = _canonical_generated_path(
                    scenario_root, delivery_relative
                )
                _atomic_write_owner_only(delivery_path, f"{name}={value}\n")
        except (KeyError, OSError, UnicodeError, ValueError):
            return LabResult(
                success=False,
                error="Generated environment binding failed containment or value validation.",
            )
        return None

    @staticmethod
    def _realize_flag_signing_keys(
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Generate the per-node flag-signing keys under their staging root.

        The staging root is the artifact's canonical source path; the mount
        model binds only each consumer's own selected key, and the
        producer-private seed is never mounted into a node.
        """

        staging_root = artifact_source_path(scenario_root, artifact)
        try:
            _canonical_generated_path(
                scenario_root, staging_root.relative_to(scenario_root.resolve())
            )
        except ValueError:
            return LabResult(
                success=False,
                error="Flag-signing key path failed containment validation.",
            )
        error = realize_flag_signing_keys(artifact, staging_root)
        if error is not None:
            return LabResult(
                success=False,
                error=f"Flag-signing key generation failed: {error}",
            )
        return None

    def _realize_certificate_bundle(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Generate and cryptographically validate a certificate bundle.

        The bundle is a scenario-local generated artifact: it is produced under
        ``scenario_root`` and read back from there (issue #874).
        """

        if artifact.provenance == SOC_CERT_PROFILE:
            return self._realize_soc_certificate_bundle(artifact, scenario_root)
        try:
            _canonical_generated_path(scenario_root, CERTIFICATE_ROOT_RELPATH)
        except ValueError:
            return LabResult(
                success=False,
                error="Certificate artifact path failed containment validation.",
            )
        result = ensure_ssl_certs(
            scenario_root,
            run_command=self._run_certificate_command,
        )
        return _certificate_bundle_failure(artifact, scenario_root, result)

    @staticmethod
    def _realize_soc_certificate_bundle(
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Generate the SOC CA + per-service certs (techvault:soc-certificate-profile/v1).

        APTL issues the SOC CA and each service certificate through the same
        ``ensure_soc_certs`` generator the in-tree lab uses (config/soc_certs);
        nothing is accepted from the pack. Every declared output must be present
        afterwards or the run fails closed (issue #875).
        """

        try:
            _canonical_generated_path(scenario_root, SOC_CERTS_ROOT_RELPATH)
        except ValueError:
            return LabResult(
                success=False,
                error="SOC certificate path failed containment validation.",
            )
        # Derive the service certificate set from the SDL-declared bundle outputs
        # rather than a hardcoded registry, so APTL never decides the range's SOC
        # service identity (issue #875, SDL-authority class remediation).
        services = derive_soc_service_certs(
            tuple(output.path for output in artifact.outputs)
        )
        result = ensure_soc_certs(scenario_root, services=services)
        failure: LabResult | None = None
        if not result.success:
            failure = LabResult(
                success=False,
                error=f"SOC certificate generation failed: {result.error}",
            )
        else:
            missing = [
                output.path
                for output in artifact.outputs
                if not (result.certs_dir / output.path).is_file()
            ]
            if missing:
                failure = LabResult(
                    success=False,
                    error=(
                        f"SOC certificate bundle {artifact.name} is missing declared "
                        f"output(s): {missing}."
                    ),
                )
        return failure

    def _run_certificate_command(
        self,
        command: list[str],
        *,
        timeout: int,
    ) -> subprocess.CompletedProcess:
        """Adapt backend timeouts to the certificate generator contract."""

        try:
            return self._run(command, timeout=timeout)
        except BackendTimeoutError as exc:
            raise subprocess.TimeoutExpired(command, timeout) from exc


def _validate_generated_scalar(value: str) -> None:
    """Reject values that cannot be represented as one Compose env assignment."""

    if (
        not value
        or len(value) > _MAX_GENERATED_VALUE_LENGTH
        or "\0" in value
        or "\n" in value
        or "\r" in value
    ):
        raise ValueError("generated environment value is invalid")


def _validate_env_file(value: str) -> None:
    """Validate a bounded assignment-only env file without exposing its values."""

    if not value or len(value) > _MAX_ENV_FILE_LENGTH or "\0" in value:
        raise ValueError("generated env file is invalid")
    names: set[str] = set()
    for line in value.splitlines():
        if not line or "=" not in line:
            raise ValueError("generated env file is invalid")
        name, _separator, secret = line.partition("=")
        if (
            _ENVIRONMENT_NAME.fullmatch(name) is None
            or name in names
            or not secret
        ):
            raise ValueError("generated env file is invalid")
        names.add(name)


def _certificate_bundle_failure(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
    result: CertResult,
) -> LabResult | None:
    """Return the first failure in a generated certificate bundle, or ``None``.

    The cryptographic bundle validator reads the in-tree provenance file
    (config/certs.yml). An env-pack declares its bundle by profile identity
    (techvault:wazuh-*-certificate-profile/v1), not a provenance document, so it
    is validated by generator success + declared-output presence; the cert
    generator issues the material itself, it is not accepted from the pack
    (issue #875).
    """

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
            error=(
                f"Generated artifact {artifact.address} is missing declared output."
            ),
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


def write_stateful_override(
    scenario_root: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> Path | None:
    """Atomically write the contained Compose stateful-resource override.

    The override is a scenario-local generated artifact, written under
    ``scenario_root`` (the bundle root), not the engine checkout (issue #874).
    """

    override_path: Path | None = None
    if realization.generated_artifacts or realization.persistent_volumes:
        payload = stateful_override_payload(scenario_root, project_name, realization)
        override_path = _canonical_generated_path(
            scenario_root,
            STATEFUL_OVERRIDE_RELPATH,
        )
        _ensure_secure_dir(override_path.parent)
        _canonical_generated_path(scenario_root, STATEFUL_OVERRIDE_RELPATH)
        _atomic_write_secure(
            override_path,
            yaml.dump(payload, Dumper=StatefulDumper, sort_keys=True),
        )
    return override_path
