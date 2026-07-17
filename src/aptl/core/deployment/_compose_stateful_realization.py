"""Docker Compose bindings for ACES stateful realization resources."""

from __future__ import annotations

from collections.abc import Mapping
import subprocess
import re
from pathlib import Path, PurePosixPath

import yaml

from aptl.core.certs import ensure_ssl_certs
from aptl.core.credentials import (
    RENDERED_MANAGER_RELPATH,
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
    sync_manager_config,
)
from aptl.core.env import env_vars_from_dict, find_placeholder_env_values, load_dotenv
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.deployment._compose_realization_networks import _compose_network_key
from aptl.core.deployment._stateful_certificates import validate_certificate_bundle
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab_types import LabResult
from aptl.core.services import check_indexer_ready, check_manager_api_ready

_STATEFUL_OVERRIDE_RELPATH = Path(".aptl/realization/compose.stateful.yml")
_CERTIFICATE_ROOT_RELPATH = Path("config/wazuh_indexer_ssl_certs")
_REALIZATION_ADDRESS_LABEL = "org.aptl.realization.address"
_REALIZATION_LIFECYCLE_LABEL = "org.aptl.realization.lifecycle"
_REALIZATION_PROJECT_LABEL = "org.aptl.realization.project"
_MIN_OVERRIDE_COMPOSE_VERSION = (2, 24, 4)


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
        errors = stateful_realization_errors(
            realization,
            local_artifacts=getattr(self, "supports_local_artifacts", True),
        )
        if not errors:
            return None
        return LabResult(success=False, error="; ".join(errors[:5]))

    def _write_stateful_realization_override(
        self,
        realization: DeploymentRealizationSpec,
    ) -> Path | None:
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

        if not _owned_wazuh_services(realization):
            return None
        result = self._run(["docker", "compose", "version", "--short"], timeout=30)
        version = _compose_version(result.stdout) if result.returncode == 0 else None
        if version is not None and version >= _MIN_OVERRIDE_COMPOSE_VERSION:
            return None
        return LabResult(
            success=False,
            error="Docker Compose 2.24.4 or later is required for stateful service ownership.",
        )

    def _stateful_teardown_compose_files(self) -> tuple[Path, ...] | None:
        """Return the persisted generated model so ``down -v`` owns its volumes."""

        override = _canonical_generated_path(
            self._project_dir,
            _STATEFUL_OVERRIDE_RELPATH,
        )
        if not override.is_file():
            return None
        return (self._project_dir / "docker-compose.yml", override)

    def _realize_stateful_prerequisites(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Materialize and verify every declared generated artifact."""

        for artifact in realization.generated_artifacts:
            if artifact.generator == "certificate_bundle":
                result = self._realize_certificate_bundle(artifact)
            else:
                result = self._realize_rendered_config(artifact)
            if result is not None:
                return result
        return None

    def _verify_stateful_authenticated_readiness(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Authenticate to realized Wazuh APIs after container health settles."""

        services = {
            consumer.service_name
            for artifact in realization.generated_artifacts
            for consumer in artifact.consumers
            if consumer.service_name in {"wazuh.indexer", "wazuh.manager"}
        }
        if not services:
            self._stateful_authenticated_readiness = {}
            return None
        try:
            raw_env = load_dotenv(self._project_dir / ".env")
            if find_placeholder_env_values(raw_env):
                raise ValueError("placeholder credentials")
            env = env_vars_from_dict(raw_env)
        except (OSError, ValueError):
            return LabResult(
                success=False,
                error="Authenticated Wazuh readiness credentials are unavailable.",
            )

        nodes = {node.service_name: node for node in realization.nodes}
        results: dict[str, bool] = {}
        for service, container_port in (
            ("wazuh.indexer", 9200),
            ("wazuh.manager", 55000),
        ):
            if service not in services:
                continue
            node = nodes.get(service)
            try:
                info = (
                    self.container_inspect(node.container_name)
                    if node is not None and node.container_name
                    else None
                )
            except (BackendTimeoutError, OSError):
                info = None
            port = _published_host_port(info, container_port)
            if port is None:
                results[service] = False
                continue
            url = f"https://localhost:{port}"
            results[service] = (
                check_indexer_ready(url, env.indexer_username, env.indexer_password)
                if service == "wazuh.indexer"
                else check_manager_api_ready(url, env.api_username, env.api_password)
            )
        self._stateful_authenticated_readiness = results
        if results and all(results.values()):
            return None
        return LabResult(
            success=False,
            error="Authenticated Wazuh readiness validation failed.",
        )

    def _realize_rendered_config(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
    ) -> LabResult | None:
        """Render the admitted manager config through ADR-028's writer."""

        if (
            artifact.provenance != "config/wazuh_cluster/wazuh_manager.conf"
            or len(artifact.outputs) != 1
            or artifact.outputs[0].path != RENDERED_MANAGER_RELPATH.name
        ):
            return LabResult(
                success=False,
                error=f"Generated artifact {artifact.address} has unsupported rendered-config binding.",
            )
        try:
            raw_env = load_dotenv(self._project_dir / ".env")
            if find_placeholder_env_values(raw_env):
                return LabResult(
                    success=False,
                    error="Rendered config rejected placeholder credential input.",
                )
            env = env_vars_from_dict(raw_env)
            output = sync_manager_config(self._project_dir, env.wazuh_cluster_key)
        except (OSError, ValueError) as exc:
            return LabResult(
                success=False,
                error=f"Rendered config materialization failed: {type(exc).__name__}.",
            )
        if not output.is_file():
            return LabResult(
                success=False,
                error=f"Generated artifact {artifact.address} is missing declared output.",
            )
        return None

    def _realize_certificate_bundle(
        self,
        artifact: DeploymentGeneratedArtifactRealization,
    ) -> LabResult | None:
        try:
            _canonical_generated_path(self._project_dir, _CERTIFICATE_ROOT_RELPATH)
        except ValueError:
            return LabResult(
                success=False,
                error="Certificate artifact path failed containment validation.",
            )
        result = ensure_ssl_certs(
            self._project_dir,
            run_command=self._run_certificate_command,
        )
        if not result.success:
            return LabResult(
                success=False, error="Certificate artifact generation failed."
            )
        if any(
            not (result.certs_dir / output.path).is_file()
            for output in artifact.outputs
        ):
            return LabResult(
                success=False,
                error=(
                    f"Generated artifact {artifact.address} is missing declared output."
                ),
            )
        errors = validate_certificate_bundle(
            result.certs_dir,
            artifact.outputs,
            self._project_dir / artifact.provenance,
        )
        if errors:
            return LabResult(success=False, error=errors[0])
        return None

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


def stateful_realization_errors(
    realization: DeploymentRealizationSpec,
    *,
    local_artifacts: bool,
) -> list[str]:
    """Return fail-closed graph errors before any backend side effect."""

    if realization.generated_artifacts and not local_artifacts:
        return [
            "Generated artifacts cannot be materialized for a remote Docker daemon."
        ]
    errors = _artifact_errors(realization)
    errors.extend(_volume_errors(realization))
    errors.extend(_dependency_errors(realization))
    errors.extend(_mount_conflicts(realization))
    errors.extend(_wazuh_definition_errors(realization))
    return errors


def write_stateful_override(
    project_dir: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> Path | None:
    """Atomically write the contained Compose stateful-resource override."""

    if not realization.generated_artifacts and not realization.persistent_volumes:
        return None
    payload = stateful_override_payload(project_dir, project_name, realization)
    override_path = _canonical_generated_path(project_dir, _STATEFUL_OVERRIDE_RELPATH)
    _ensure_secure_dir(override_path.parent)
    _canonical_generated_path(project_dir, _STATEFUL_OVERRIDE_RELPATH)
    _atomic_write_secure(
        override_path,
        yaml.dump(payload, Dumper=_StatefulDumper, sort_keys=True),
    )
    return override_path


def stateful_override_payload(
    project_dir: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> dict[str, object]:
    """Return the complete generated stateful Compose model."""

    services: dict[str, dict[str, object]] = _wazuh_service_definitions(
        project_dir, realization
    )
    for artifact in realization.generated_artifacts:
        source = artifact_source_path(project_dir, artifact)
        for consumer in artifact.consumers:
            if artifact.generator == "certificate_bundle":
                for output in artifact.outputs:
                    _mounts(services, consumer.service_name).append(
                        {
                            "type": "bind",
                            "source": str(source / output.path),
                            "target": str(
                                PurePosixPath(consumer.mount_destination) / output.path
                            ),
                            "read_only": True,
                        }
                    )
            else:
                _mounts(services, consumer.service_name).append(
                    {
                        "type": "bind",
                        "source": str(source),
                        "target": consumer.mount_destination,
                        "read_only": True,
                    }
                )
    volumes: dict[str, dict[str, object]] = {}
    for volume in realization.persistent_volumes:
        volumes[volume.name] = {
            "labels": {
                _REALIZATION_ADDRESS_LABEL: volume.address,
                _REALIZATION_LIFECYCLE_LABEL: volume.lifecycle,
                _REALIZATION_PROJECT_LABEL: project_name,
            }
        }
        for consumer in volume.consumers:
            _mounts(services, consumer.service_name).append(
                {
                    "type": "volume",
                    "source": volume.name,
                    "target": consumer.mount_destination,
                    "read_only": consumer.access_mode == "read_only",
                }
            )
    payload: dict[str, object] = {"services": services}
    if volumes:
        payload["volumes"] = volumes
    return payload


def effective_stateful_model_errors(
    payload: object,
    project_dir: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Validate the in-memory effective Compose model against admitted state."""

    if not isinstance(payload, Mapping):
        return ["Effective Compose model is not a mapping."]
    observed_services = payload.get("services")
    if not isinstance(observed_services, Mapping):
        return ["Effective Compose model has no services mapping."]
    expected_payload = stateful_override_payload(
        project_dir, project_name, realization
    )
    expected_services = expected_payload["services"]
    assert isinstance(expected_services, Mapping)
    errors: list[str] = []
    for service_name, expected_service in expected_services.items():
        observed_service = observed_services.get(service_name)
        if not isinstance(expected_service, Mapping) or not isinstance(
            observed_service, Mapping
        ):
            errors.append(f"Effective stateful service {service_name} is absent.")
            continue
        if service_name in {"wazuh.indexer", "wazuh.manager"}:
            errors.extend(
                _owned_service_model_errors(
                    service_name, expected_service, observed_service
                )
            )
        elif not _mount_contract(expected_service).issubset(
            _mount_contract(observed_service)
        ):
            errors.append(
                f"Effective stateful service {service_name} is missing a declared mount."
            )
    errors.extend(
        _certificate_exposure_errors(
            observed_services, project_dir, realization
        )
    )
    errors.extend(_effective_volume_errors(payload, project_name, realization))
    return errors


def _owned_service_model_errors(
    service_name: str,
    expected: Mapping[str, object],
    observed: Mapping[str, object],
) -> list[str]:
    errors: list[str] = []
    fields = (
        "image",
        "container_name",
        "hostname",
        "restart",
        "profiles",
        "ports",
        "environment",
        "ulimits",
        "healthcheck",
        "deploy",
        "networks",
    )
    if any(observed.get(field) != expected.get(field) for field in fields):
        errors.append(
            f"Effective stateful service {service_name} does not match its admitted definition."
        )
    if _normalized_dependencies(observed.get("depends_on")) != (
        _normalized_dependencies(expected.get("depends_on"))
    ):
        errors.append(
            f"Effective stateful service {service_name} has unexpected dependencies."
        )
    if _mount_contract(observed) != _mount_contract(expected):
        errors.append(
            f"Effective stateful service {service_name} has unexpected mounts."
        )
    return errors


def _mount_contract(service: Mapping[str, object]) -> set[tuple[object, ...]]:
    mounts = service.get("volumes")
    if not isinstance(mounts, list):
        return set()
    return {
        (
            mount.get("type"),
            mount.get("source"),
            mount.get("target"),
            bool(mount.get("read_only")),
        )
        for mount in mounts
        if isinstance(mount, Mapping)
    }


def _normalized_dependencies(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {
        str(service): str(details.get("condition"))
        for service, details in value.items()
        if isinstance(details, Mapping)
    }


def _certificate_exposure_errors(
    services: Mapping[object, object],
    project_dir: Path,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    cert_root = str(project_dir.resolve() / _CERTIFICATE_ROOT_RELPATH)
    expected: dict[str, set[tuple[str, str]]] = {}
    for artifact in realization.generated_artifacts:
        if artifact.generator != "certificate_bundle":
            continue
        for consumer in artifact.consumers:
            expected.setdefault(consumer.service_name, set()).update(
                {
                    (
                        str(Path(cert_root) / output.path),
                        str(PurePosixPath(consumer.mount_destination) / output.path),
                    )
                    for output in artifact.outputs
                }
            )
    errors: list[str] = []
    for service_name, allowed in expected.items():
        service = services.get(service_name)
        if not isinstance(service, Mapping):
            continue
        mounts = service.get("volumes")
        if not isinstance(mounts, list):
            mounts = []
        observed = {
            (str(mount.get("source")), str(mount.get("target")))
            for mount in mounts
            if isinstance(mount, Mapping)
            and (
                str(mount.get("source")) == cert_root
                or str(mount.get("source", "")).startswith(f"{cert_root}/")
            )
        }
        if observed != allowed:
            errors.append(
                f"Effective stateful service {service_name} exposes undeclared certificate material."
            )
    return errors


def _effective_volume_errors(
    payload: Mapping[str, object],
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    if not realization.persistent_volumes:
        return []
    observed = payload.get("volumes")
    if not isinstance(observed, Mapping):
        return ["Effective Compose model has no volumes mapping."]
    errors: list[str] = []
    for volume in realization.persistent_volumes:
        definition = observed.get(volume.name)
        labels = definition.get("labels") if isinstance(definition, Mapping) else None
        name = definition.get("name") if isinstance(definition, Mapping) else None
        expected_labels = {
            _REALIZATION_ADDRESS_LABEL: volume.address,
            _REALIZATION_LIFECYCLE_LABEL: volume.lifecycle,
            _REALIZATION_PROJECT_LABEL: project_name,
        }
        if labels != expected_labels or name != f"{project_name}_{volume.name}":
            errors.append(
                f"Effective persistent volume {volume.address} has unexpected identity."
            )
    return errors


def artifact_source_path(
    project_dir: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> Path:
    """Return the canonical host source for a supported artifact provider."""

    relative = (
        _CERTIFICATE_ROOT_RELPATH
        if artifact.generator == "certificate_bundle"
        else RENDERED_MANAGER_RELPATH
    )
    return project_dir.resolve() / relative


def _mounts(
    services: dict[str, dict[str, object]],
    service_name: str,
) -> list[dict[str, object]]:
    service = services.setdefault(service_name, {"volumes": []})
    volumes = service.setdefault("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("Generated service volumes are not a list.")
    return volumes


def _owned_wazuh_services(realization: DeploymentRealizationSpec) -> set[str]:
    return {
        consumer.service_name
        for resource in (
            *realization.generated_artifacts,
            *realization.persistent_volumes,
        )
        for consumer in resource.consumers
        if consumer.service_name in {"wazuh.indexer", "wazuh.manager"}
    }


def _compose_version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(?:v)?(\d+)\.(\d+)\.(\d+)", value)
    return tuple(map(int, match.groups())) if match else None


def _wazuh_definition_errors(realization: DeploymentRealizationSpec) -> list[str]:
    owned = _owned_wazuh_services(realization)
    if not owned:
        return []
    nodes = {node.service_name: node for node in realization.nodes}
    images = {image.service_name for image in realization.images}
    errors: list[str] = []
    for service in sorted(owned):
        node = nodes.get(service)
        if node is None or not node.container_name or not node.network_attachments:
            errors.append(
                f"Stateful service {service} has an incomplete node definition."
            )
        if service not in images:
            errors.append(
                f"Stateful service {service} has no trusted image realization."
            )
    manager = nodes.get("wazuh.manager")
    indexer = nodes.get("wazuh.indexer")
    if manager is not None and "wazuh.manager" in owned:
        if indexer is None or indexer.address not in manager.ordering_dependencies:
            errors.append("Wazuh manager does not depend on the realized indexer node.")
    return errors


class _OverrideMapping(dict):
    """A complete Compose service definition that replaces the base service."""


class _StatefulDumper(yaml.SafeDumper):
    """Safe YAML dumper with Compose's explicit replacement tag."""


_StatefulDumper.add_representer(
    _OverrideMapping,
    lambda dumper, value: dumper.represent_mapping("!override", value),
)


def _wazuh_service_definitions(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
) -> dict[str, dict[str, object]]:
    """Build complete manager/indexer definitions from the admitted DTO graph."""

    consumers = {
        consumer.service_name
        for resource in (
            *realization.generated_artifacts,
            *realization.persistent_volumes,
        )
        for consumer in resource.consumers
    }
    owned = consumers & {"wazuh.indexer", "wazuh.manager"}
    if not owned:
        return {}
    nodes = {node.service_name: node for node in realization.nodes if node.service_name}
    images = {image.service_name: image.image_ref for image in realization.images}
    services: dict[str, dict[str, object]] = {}
    if "wazuh.indexer" in owned:
        node = nodes["wazuh.indexer"]
        services["wazuh.indexer"] = _OverrideMapping(
            {
                "profiles": ["wazuh"],
                "container_name": node.container_name,
                "hostname": "wazuh.indexer",
                "image": images["wazuh.indexer"],
                "restart": "always",
                "ports": ["127.0.0.1:${APTL_HP_WAZUH_INDEXER_9200:-9200}:9200"],
                "environment": ["OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"],
                "ulimits": {
                    "memlock": {"soft": -1, "hard": -1},
                    "nofile": {"soft": 65536, "hard": 65536},
                },
                "volumes": [
                    _bind(
                        project_dir,
                        "config/wazuh_indexer/wazuh.indexer.yml",
                        "/usr/share/wazuh-indexer/opensearch.yml",
                    ),
                    _bind(
                        project_dir,
                        "config/wazuh_indexer/internal_users.yml",
                        "/usr/share/wazuh-indexer/opensearch-security/internal_users.yml",
                    ),
                ],
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "curl -ks https://localhost:9200 || exit 1",
                    ],
                    "interval": "30s",
                    "timeout": "10s",
                    "retries": 10,
                    "start_period": "180s",
                },
                "deploy": {"resources": {"limits": {"memory": "2g"}}},
                "networks": _service_networks(node),
            }
        )
    if "wazuh.manager" in owned:
        node = nodes["wazuh.manager"]
        services["wazuh.manager"] = _OverrideMapping(
            {
                "profiles": ["wazuh"],
                "container_name": node.container_name,
                "hostname": "wazuh.manager",
                "image": images["wazuh.manager"],
                "restart": "always",
                "ports": _manager_ports(node),
                "environment": [
                    "INDEXER_URL=https://wazuh.indexer:9200",
                    "INDEXER_USERNAME=${INDEXER_USERNAME}",
                    "INDEXER_PASSWORD=${INDEXER_PASSWORD}",
                    "FILEBEAT_SSL_VERIFICATION_MODE=full",
                    "SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/wazuh/root-ca-manager.pem",
                    "SSL_CERTIFICATE=/etc/ssl/wazuh/wazuh.manager.pem",
                    "SSL_KEY=/etc/ssl/wazuh/wazuh.manager-key.pem",
                    "API_USERNAME=${API_USERNAME}",
                    "API_PASSWORD=${API_PASSWORD}",
                ],
                "ulimits": {
                    "memlock": {"soft": -1, "hard": -1},
                    "nofile": {"soft": 655360, "hard": 655360},
                },
                "volumes": [
                    _bind(
                        project_dir,
                        "config/wazuh_cluster/filebeat_wazuh_module.yml",
                        "/run/filebeat-override.yml",
                    ),
                    _bind(
                        project_dir,
                        "config/wazuh_cluster/patch-rule-path.py",
                        "/docker-entrypoint-initdb.d/patch-rule-path.py",
                    ),
                ],
                "entrypoint": [
                    "/bin/bash",
                    "-c",
                    "cp /run/filebeat-override.yml /etc/filebeat/filebeat.yml && chown root:root /etc/filebeat/filebeat.yml && python3 /docker-entrypoint-initdb.d/patch-rule-path.py 2>/dev/null; exec /init",
                ],
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "curl -ks https://localhost:55000 || exit 1",
                    ],
                    "interval": "30s",
                    "timeout": "10s",
                    "retries": 5,
                    "start_period": "120s",
                },
                "deploy": {"resources": {"limits": {"memory": "1g"}}},
                "depends_on": _service_dependencies(node, realization.nodes),
                "networks": _service_networks(node),
            }
        )
    return services


def _bind(project_dir: Path, source: str, target: str) -> dict[str, object]:
    return {
        "type": "bind",
        "source": str(project_dir.resolve() / source),
        "target": target,
        "read_only": True,
    }


def _service_networks(node: DeploymentNodeRealization) -> dict[str, object]:
    return {
        _compose_network_key(attachment.network): (
            {"ipv4_address": attachment.ipv4_address}
            if attachment.ipv4_address
            else None
        )
        for attachment in node.network_attachments
    }


def _service_dependencies(
    node: DeploymentNodeRealization,
    nodes: tuple[DeploymentNodeRealization, ...],
) -> dict[str, dict[str, str]]:
    services_by_address = {
        candidate.address: candidate.service_name
        for candidate in nodes
        if candidate.service_name
    }
    return {
        service: {"condition": "service_healthy"}
        for address in node.ordering_dependencies
        if (service := services_by_address.get(address))
    }


def _manager_ports(node: DeploymentNodeRealization) -> list[str]:
    declared = {(service.port, service.protocol) for service in node.services}
    env_names = {
        (1514, "tcp"): "APTL_HP_WAZUH_MANAGER_1514",
        (1515, "tcp"): "APTL_HP_WAZUH_MANAGER_1515",
        (514, "udp"): "APTL_HP_WAZUH_MANAGER_514",
        (55000, "tcp"): "APTL_HP_WAZUH_MANAGER_55000",
    }
    return [
        (
            f"127.0.0.1:${{{env_names[(port, protocol)]}:-{port}}}:{port}"
            + ("/udp" if protocol == "udp" else "")
        )
        for port, protocol in sorted(declared)
        if (port, protocol) in env_names
    ]


def _artifact_errors(realization: DeploymentRealizationSpec) -> list[str]:
    errors: list[str] = []
    for artifact in realization.generated_artifacts:
        if (
            artifact.generator == "certificate_bundle"
            and artifact.provenance != "config/certs.yml"
        ):
            errors.append(
                f"Generated artifact {artifact.address} has unsupported provenance."
            )
        if artifact.generator == "rendered_config" and len(artifact.outputs) != 1:
            errors.append(
                f"Rendered config {artifact.address} must declare exactly one output."
            )
        if any(consumer.access_mode != "read_only" for consumer in artifact.consumers):
            errors.append(
                f"Generated artifact {artifact.address} must be mounted read-only."
            )
        if any(not _safe_relative(output.path) for output in artifact.outputs):
            errors.append(
                f"Generated artifact {artifact.address} has an unsafe output path."
            )
    return errors


def _volume_errors(realization: DeploymentRealizationSpec) -> list[str]:
    errors: list[str] = []
    for volume in realization.persistent_volumes:
        writers = {
            consumer.target_address
            for consumer in volume.consumers
            if consumer.access_mode == "read_write"
        }
        if volume.access_mode == "read_write_once" and len(writers) > 1:
            errors.append(
                f"Persistent volume {volume.address} has multiple writer nodes."
            )
        if volume.access_mode == "read_only_many" and writers:
            errors.append(
                f"Persistent volume {volume.address} is read-only but has a writer."
            )
    return errors


def _dependency_errors(realization: DeploymentRealizationSpec) -> list[str]:
    resources = {
        item.address: item
        for item in (*realization.generated_artifacts, *realization.persistent_volumes)
    }
    errors: list[str] = []
    for resource in resources.values():
        dependencies = (*resource.ordering_dependencies, *resource.refresh_dependencies)
        if set(dependencies) - set(resources):
            errors.append(
                f"Stateful resource {resource.address} has an unresolved dependency."
            )
    if _has_ordering_cycle(resources):
        errors.append("Stateful realization ordering dependencies contain a cycle.")
    return errors


def _has_ordering_cycle(resources: dict[str, object]) -> bool:
    pending = {
        address: set(getattr(resource, "ordering_dependencies", ()))
        for address, resource in resources.items()
    }
    while pending:
        ready = {
            address for address, dependencies in pending.items() if not dependencies
        }
        if not ready:
            return True
        pending = {
            address: dependencies - ready
            for address, dependencies in pending.items()
            if address not in ready
        }
    return False


def _mount_conflicts(realization: DeploymentRealizationSpec) -> list[str]:
    occupied: set[tuple[str, str]] = set()
    for resource in (*realization.generated_artifacts, *realization.persistent_volumes):
        for consumer in resource.consumers:
            destination = (consumer.target_address, consumer.mount_destination)
            if destination in occupied:
                return ["Stateful resources claim the same consumer mount destination."]
            occupied.add(destination)
    return []


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        value
        and not path.is_absolute()
        and ".." not in path.parts
        and str(path) == value
        and "\\" not in value
    )


def _published_host_port(info: object, container_port: int) -> int | None:
    """Read one TCP host binding from container inspect output."""

    if not isinstance(info, dict):
        return None
    network_settings = info.get("NetworkSettings")
    if not isinstance(network_settings, dict):
        return None
    ports = network_settings.get("Ports")
    if not isinstance(ports, dict):
        return None
    bindings = ports.get(f"{container_port}/tcp")
    if not isinstance(bindings, list) or not bindings:
        return None
    binding = bindings[0]
    if not isinstance(binding, dict):
        return None
    value = binding.get("HostPort")
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None
