"""Docker Compose bindings for ACES stateful realization resources."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from aptl.core.certs import ensure_ssl_certs
from aptl.core.credentials import (
    RENDERED_MANAGER_RELPATH,
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
    sync_manager_config,
)
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_ROOT_RELPATH,
    MIN_OVERRIDE_COMPOSE_VERSION,
    STATEFUL_OVERRIDE_RELPATH,
    WAZUH_INDEXER_SERVICE,
    WAZUH_MANAGER_SERVICE,
)
from aptl.core.deployment._compose_stateful_graph import (
    compose_version,
    owned_wazuh_services,
    stateful_realization_errors,
)
from aptl.core.deployment._compose_stateful_model import (
    artifact_source_path,
    effective_stateful_model_errors,
    stateful_override_payload,
)
from aptl.core.deployment._compose_stateful_services import StatefulDumper
from aptl.core.deployment._stateful_certificates import validate_certificate_bundle
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.env import (
    EnvVars,
    env_vars_from_dict,
    find_placeholder_env_values,
    load_dotenv,
)
from aptl.core.lab_types import LabResult
from aptl.core.services import check_indexer_ready, check_manager_api_ready


class ComposeStatefulRealizationMixin:
    """Validate and bind typed stateful resources before Compose startup."""

    @property
    def authenticated_readiness(self) -> dict[str, bool]:
        """Return non-secret authenticated readiness observed this realization."""

        return dict(getattr(self, "_stateful_authenticated_readiness", {}))

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
    ) -> Path | None:
        """Persist the stateful Compose override when resources require one."""

        return write_stateful_override(
            self._project_dir,
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

    def _stateful_teardown_compose_files(self) -> tuple[Path, ...] | None:
        """Return the persisted generated model so ``down -v`` owns its volumes."""

        override = _canonical_generated_path(
            self._project_dir,
            STATEFUL_OVERRIDE_RELPATH,
        )
        if not override.is_file():
            return None
        return (self._project_dir / "docker-compose.yml", override)

    def _realize_stateful_prerequisites(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Materialize and verify every declared generated artifact."""

        failure: LabResult | None = None
        for artifact in realization.generated_artifacts:
            failure = (
                self._realize_certificate_bundle(artifact)
                if artifact.generator == "certificate_bundle"
                else self._realize_rendered_config(artifact)
            )
            if failure is not None:
                break
        return failure

    def _verify_stateful_authenticated_readiness(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Authenticate to realized Wazuh APIs after container health settles."""

        services = {
            consumer.service_name
            for artifact in realization.generated_artifacts
            for consumer in artifact.consumers
            if consumer.service_name in {WAZUH_INDEXER_SERVICE, WAZUH_MANAGER_SERVICE}
        }
        results: dict[str, bool] = {}
        env: EnvVars | None = None
        if services:
            env, _placeholder_input = _load_stateful_env(self._project_dir)
        failure: LabResult | None = None
        if services and env is None:
            failure = LabResult(
                success=False,
                error="Authenticated Wazuh readiness credentials are unavailable.",
            )
        elif services and env is not None:
            nodes = {node.service_name: node for node in realization.nodes}
            results = self._authenticated_readiness_results(services, nodes, env)
        self._stateful_authenticated_readiness = results
        if failure is None and results and not all(results.values()):
            failure = LabResult(
                success=False,
                error="Authenticated Wazuh readiness validation failed.",
            )
        return failure

    def _authenticated_readiness_results(
        self,
        services: set[str],
        nodes: dict[str | None, DeploymentNodeRealization],
        env: EnvVars,
    ) -> dict[str, bool]:
        """Return authenticated readiness for each graph-owned Wazuh service."""

        checks = (
            (WAZUH_INDEXER_SERVICE, 9200),
            (WAZUH_MANAGER_SERVICE, 55000),
        )
        return {
            service: self._authenticated_service_ready(
                service,
                port,
                nodes.get(service),
                env,
            )
            for service, port in checks
            if service in services
        }

    def _authenticated_service_ready(
        self,
        service: str,
        container_port: int,
        node: DeploymentNodeRealization | None,
        env: EnvVars,
    ) -> bool:
        """Probe one graph-owned Wazuh API with the configured credentials."""

        info: object = None
        if node is not None and node.container_name:
            try:
                info = self.container_inspect(node.container_name)
            except (BackendTimeoutError, OSError):
                info = None
        port = _published_host_port(info, container_port)
        ready = False
        if port is not None:
            url = f"https://localhost:{port}"
            if service == WAZUH_INDEXER_SERVICE:
                ready = check_indexer_ready(
                    url,
                    env.indexer_username,
                    env.indexer_password,
                )
            else:
                ready = check_manager_api_ready(
                    url,
                    env.api_username,
                    env.api_password,
                )
        return ready

    def _realize_rendered_config(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
    ) -> LabResult | None:
        """Render the admitted manager config through ADR-028's writer."""

        unsupported_binding = (
            artifact.provenance != "config/wazuh_cluster/wazuh_manager.conf"
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
                        self._project_dir,
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

    def _realize_certificate_bundle(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
    ) -> LabResult | None:
        """Generate and cryptographically validate a certificate bundle."""

        failure: LabResult | None = None
        try:
            _canonical_generated_path(self._project_dir, CERTIFICATE_ROOT_RELPATH)
        except ValueError:
            failure = LabResult(
                success=False,
                error="Certificate artifact path failed containment validation.",
            )
        result = None
        if failure is None:
            result = ensure_ssl_certs(
                self._project_dir,
                run_command=self._run_certificate_command,
            )
            if not result.success:
                failure = LabResult(
                    success=False,
                    error="Certificate artifact generation failed.",
                )
        if (
            failure is None
            and result is not None
            and any(
                not (result.certs_dir / output.path).is_file()
                for output in artifact.outputs
            )
        ):
            failure = LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} is missing declared output."
                ),
            )
        if failure is None and result is not None:
            errors = validate_certificate_bundle(
                result.certs_dir,
                artifact.outputs,
                self._project_dir / artifact.provenance,
            )
            if errors:
                failure = LabResult(success=False, error=errors[0])
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


def write_stateful_override(
    project_dir: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> Path | None:
    """Atomically write the contained Compose stateful-resource override."""

    override_path: Path | None = None
    if realization.generated_artifacts or realization.persistent_volumes:
        payload = stateful_override_payload(project_dir, project_name, realization)
        override_path = _canonical_generated_path(
            project_dir,
            STATEFUL_OVERRIDE_RELPATH,
        )
        _ensure_secure_dir(override_path.parent)
        _canonical_generated_path(project_dir, STATEFUL_OVERRIDE_RELPATH)
        _atomic_write_secure(
            override_path,
            yaml.dump(payload, Dumper=StatefulDumper, sort_keys=True),
        )
    return override_path


def _load_stateful_env(project_dir: Path) -> tuple[EnvVars | None, bool]:
    """Load typed credentials and report whether placeholders caused rejection."""

    env: EnvVars | None = None
    placeholder_input = False
    try:
        raw_env = load_dotenv(project_dir / ".env")
        placeholder_input = bool(find_placeholder_env_values(raw_env))
        if not placeholder_input:
            env = env_vars_from_dict(raw_env)
    except (OSError, ValueError):
        env = None
    return env, placeholder_input


def _published_host_port(info: object, container_port: int) -> int | None:
    """Read one TCP host binding from container inspect output."""

    port: int | None = None
    if isinstance(info, dict):
        network_settings = info.get("NetworkSettings")
        ports = (
            network_settings.get("Ports")
            if isinstance(network_settings, dict)
            else None
        )
        bindings = (
            ports.get(f"{container_port}/tcp") if isinstance(ports, dict) else None
        )
        binding = bindings[0] if isinstance(bindings, list) and bindings else None
        value = binding.get("HostPort") if isinstance(binding, dict) else None
        try:
            candidate = int(value)
        except (TypeError, ValueError):
            candidate = 0
        if 1 <= candidate <= 65535:
            port = candidate
    return port
