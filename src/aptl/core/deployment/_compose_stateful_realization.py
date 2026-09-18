"""Docker Compose bindings for RAES stateful realization resources."""

from __future__ import annotations

import subprocess
from pathlib import Path

from aptl.core.certs import CertResult, ensure_ssl_certs
from aptl.core.deployment._authored_service_hosts import authored_service_hosts
from aptl.core.soc_ca import derive_soc_service_certs, ensure_soc_certs
from aptl.core.credentials import (
    RENDERED_MANAGER_RELPATH,
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
    sync_manager_config,
)
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_PROVENANCE,
    CERTIFICATE_ROOT_RELPATH,
    MIN_OVERRIDE_COMPOSE_VERSION,
    SOC_CERT_PROFILE,
    SOC_CERTS_ROOT_RELPATH,
    WAZUH_MANAGER_CONFIG_PROVENANCES,
)
from aptl.core.deployment._compose_stateful_graph import (
    compose_version,
    owned_wazuh_services,
    stateful_realization_errors,
)
from aptl.core.deployment._compose_stateful_constants import (
    ENVIRONMENT_DELIVERY_PROVENANCES as _ENVIRONMENT_DELIVERY_PROVENANCES,
)
from aptl.core.deployment._compose_stateful_model import (
    artifact_environment_file_path,
    artifact_source_path as _artifact_source_path,
    effective_stateful_model_errors as _effective_stateful_model_errors,
    stateful_override_payload as _stateful_override_payload,
)
from aptl.core.deployment._compose_stateful_override import write_stateful_override
from aptl.core.deployment._cortex_service_credentials import (
    CORTEX_SERVICE_CREDENTIALS_PROFILE,
    realize_cortex_service_credentials,
)
from aptl.core.deployment._misp_cache_credential import (
    MISP_CACHE_CREDENTIAL_PROFILE,
    realize_misp_cache_credential,
)
from aptl.core.deployment._misp_server_tls import (
    MISP_SERVER_TLS_PROFILE,
    realize_misp_server_tls,
)
from aptl.core.deployment._compose_stateful_readiness import (
    ComposeStatefulReadinessMixin,
    _load_stateful_env,
)
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
    valid_environment_variable_name,
)
from aptl.core.lab_types import LabResult

artifact_source_path = _artifact_source_path
effective_stateful_model_errors = _effective_stateful_model_errors
stateful_override_payload = _stateful_override_payload


def _artifacts_in_dependency_order(
    artifacts: tuple[DeploymentGeneratedArtifactRealization, ...],
) -> tuple[DeploymentGeneratedArtifactRealization, ...]:
    """Order artifacts so each one is produced after what it depends on.

    The realization spec sorts artifacts by address because that is a stable
    canonical order for a document, not a safe execution order: an artifact
    whose address happens to sort earlier than its producer would otherwise run
    first and read material that does not exist yet.

    Ties are broken by address so the result stays deterministic, and a
    dependency that names nothing in this set is ignored rather than treated as
    a cycle -- ordering references also point at persistent volumes, which are
    realized separately. A genuine cycle cannot be ordered, so the remaining
    artifacts keep their canonical order and their own producers fail closed
    rather than being silently dropped.
    """

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
    """Resolve one ordering reference to an artifact address in this set.

    Authored dependencies arrive as resolved addresses, while a backend-selected
    artifact names its producer the way the SDL does, as
    ``generated_artifacts.<name>``. Both forms identify the same artifact, so
    both resolve here instead of one of them silently matching nothing.
    """

    if reference in artifacts:
        return reference
    name = reference.rsplit(".", 1)[-1]
    matches = [
        address for address, artifact in artifacts.items() if artifact.name == name
    ]
    return matches[0] if len(matches) == 1 else None


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
        for artifact in _artifacts_in_dependency_order(
            realization.generated_artifacts
        ):
            failure = self._realize_one_generated_artifact(
                artifact, scenario_root, realization
            )
            if failure is not None:
                break
        return failure

    def _realize_one_generated_artifact(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Materialize one generated artifact, dispatched by generator kind."""

        realizer = {
            "certificate_bundle": lambda item, root: self._realize_certificate_bundle(
                item, root, realization
            ),
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
        if failure is None and artifact.environment_consumers:
            failure = self._realize_artifact_environment_files(artifact, scenario_root)
        return failure

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
        if artifact.provenance == CORTEX_SERVICE_CREDENTIALS_PROFILE:
            error = realize_cortex_service_credentials(artifact, scenario_root)
            return LabResult(success=False, error=error) if error is not None else None
        if artifact.provenance == MISP_CACHE_CREDENTIAL_PROFILE:
            error = realize_misp_cache_credential(artifact, scenario_root)
            return LabResult(success=False, error=error) if error is not None else None
        if artifact.provenance == MISP_SERVER_TLS_PROFILE:
            error = realize_misp_server_tls(artifact, scenario_root)
            return LabResult(success=False, error=error) if error is not None else None
        return self._realize_wazuh_config(artifact, scenario_root)

    def _realize_wazuh_config(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Render and verify one Wazuh manager configuration artifact."""

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
    def _realize_artifact_environment_files(
        artifact: DeploymentGeneratedArtifactRealization,
        scenario_root: Path,
    ) -> LabResult | None:
        """Write exact output-to-variable bindings without putting secrets in YAML."""

        failure = None
        if artifact.provenance not in _ENVIRONMENT_DELIVERY_PROVENANCES:
            failure = LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} has unsupported "
                    "environment delivery."
                ),
            )
        else:
            try:
                by_service = _artifact_environment_bindings(artifact, scenario_root)
                _write_artifact_environment_files(artifact, scenario_root, by_service)
            except (OSError, ValueError):
                failure = LabResult(
                    success=False,
                    error=f"Generated artifact {artifact.address} environment delivery failed.",
                )
        return failure

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
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Generate and cryptographically validate a certificate bundle.

        The bundle is a scenario-local generated artifact: it is produced under
        ``scenario_root`` and read back from there (issue #874).
        """

        if artifact.provenance == SOC_CERT_PROFILE:
            return self._realize_soc_certificate_bundle(
                artifact, scenario_root, realization
            )
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
        realization: DeploymentRealizationSpec,
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
            tuple(output.path for output in artifact.outputs),
            authored_service_hosts(realization),
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


def _artifact_environment_bindings(
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


def _write_artifact_environment_files(
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
