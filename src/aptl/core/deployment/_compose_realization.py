"""Docker Compose realization helpers for typed ACES deployment specs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab_types import LabResult

_NETWORK_TOKEN_SEPARATORS = re.compile(r"[^a-z0-9]+")
_REALIZATION_TIMEOUT = 30
_IMAGE_REALIZATION_TIMEOUT = 600
_IMAGE_OVERRIDE_RELATIVE_PATH = Path(".aptl") / "realization" / "compose-images.yml"
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_NETWORK_LABEL = "com.docker.compose.network"
_REALIZATION_NETWORK_LABEL = "org.aptl.realization.network"
_REALIZATION_NETWORK_LABEL_VALUE = "true"


def _container_networks(container_info: dict[str, Any]) -> set[str]:
    """Return Docker network names from one container inspect payload."""

    networks = (
        container_info.get("NetworkSettings", {}).get("Networks")
        if isinstance(container_info, dict)
        else None
    )
    if not isinstance(networks, dict):
        return set()
    return {str(network_name) for network_name in networks if str(network_name)}


def _container_network_ip(
    container_info: dict[str, Any],
    network_name: str,
) -> str:
    """Return a container's IPv4 address on one Docker network."""

    networks = (
        container_info.get("NetworkSettings", {}).get("Networks")
        if isinstance(container_info, dict)
        else None
    )
    if not isinstance(networks, dict):
        return ""
    endpoint = networks.get(network_name)
    if not isinstance(endpoint, dict):
        return ""
    address = endpoint.get("IPAddress")
    return address if isinstance(address, str) else ""


def _resolve_realization_networks(
    declared_networks: tuple[str, ...],
    managed_networks: set[str],
    project_name: str,
) -> tuple[set[str], list[str]]:
    """Resolve ACES network names to concrete project Docker network names."""

    desired: set[str] = set()
    missing: list[str] = []
    for declared in declared_networks:
        match = _match_managed_network(declared, managed_networks, project_name)
        if match is None:
            missing.append(declared)
        else:
            desired.add(match)
    return desired, missing


def _resolve_realization_network_attachments(
    attachments: tuple[DeploymentNetworkAttachment, ...],
    managed_networks: set[str],
    project_name: str,
) -> tuple[dict[str, DeploymentNetworkAttachment], list[str]]:
    """Resolve declared attachments to concrete backend network names."""

    desired: dict[str, DeploymentNetworkAttachment] = {}
    missing: list[str] = []
    for attachment in attachments:
        match = _match_managed_network(
            attachment.network,
            managed_networks,
            project_name,
        )
        if match is None:
            missing.append(attachment.network)
        else:
            desired[match] = attachment
    return desired, missing


def _match_managed_network(
    declared: str,
    managed_networks: set[str],
    project_name: str,
) -> str | None:
    """Return the managed Docker network matching an ACES declaration."""

    for candidate in _network_name_candidates(declared, project_name):
        if candidate in managed_networks:
            return candidate
    return None


def _network_name_candidates(declared: str, project_name: str) -> tuple[str, ...]:
    """Return likely Compose network names for an ACES network identifier."""

    normalized = _network_token(declared)
    if not normalized:
        return ()
    stems = {normalized}
    if normalized.endswith("-net"):
        stems.add(normalized.removesuffix("-net"))
    if normalized.startswith("aptl-"):
        stems.add(normalized.removeprefix("aptl-"))
    candidates: list[str] = []
    for stem in sorted(stems):
        candidates.extend(
            [
                stem,
                f"aptl-{stem}",
                f"{project_name}_{stem}",
                f"{project_name}_aptl-{stem}",
                f"{project_name}-{stem}",
                f"{project_name}-aptl-{stem}",
            ]
        )
    return tuple(dict.fromkeys(candidates))


def _network_token(raw: str) -> str:
    """Normalize a network identifier for candidate-name generation."""

    return _NETWORK_TOKEN_SEPARATORS.sub("-", raw.strip().lower()).strip("-")


def _network_stem(raw: str) -> str:
    """Return the APTL network stem used for concrete backend names."""

    normalized = _network_token(raw)
    if normalized.endswith("-net"):
        normalized = normalized.removesuffix("-net")
    if normalized.startswith("aptl-"):
        normalized = normalized.removeprefix("aptl-")
    return normalized


def _compose_network_key(declared: str) -> str:
    """Return the Compose-style network key for one declared network."""

    stem = _network_stem(declared)
    return f"aptl-{stem}" if stem else ""


def _concrete_network_name(declared: str, project_name: str) -> str:
    """Return the project-scoped Docker network name for a declaration."""

    key = _compose_network_key(declared)
    return f"{project_name}_{key}" if key else ""


def _network_policy_mismatches(
    details: dict[str, Any],
    labels: dict[str, Any],
    network: DeploymentNetworkRealization,
    *,
    project_name: str,
    compose_key: str,
) -> list[str]:
    """Return mismatches between Docker state and typed network intent."""

    mismatches: list[str] = []
    expected_labels = {
        _COMPOSE_PROJECT_LABEL: project_name,
        _COMPOSE_NETWORK_LABEL: compose_key,
        _REALIZATION_NETWORK_LABEL: _REALIZATION_NETWORK_LABEL_VALUE,
    }
    for label, expected in expected_labels.items():
        actual = labels.get(label, "")
        if actual != expected:
            mismatches.append(
                f"label {label} expected {expected!r}, found {actual!r}"
            )
    if network.internal is not None and (
        bool(details.get("internal")) != network.internal
    ):
        mismatches.append(
            "internal expected "
            f"{network.internal!r}, found {bool(details.get('internal'))!r}"
        )
    if network.cidr and details.get("subnet", "") != network.cidr:
        mismatches.append(
            f"subnet expected {network.cidr!r}, found {details.get('subnet', '')!r}"
        )
    if network.gateway and details.get("gateway", "") != network.gateway:
        mismatches.append(
            "gateway expected "
            f"{network.gateway!r}, found {details.get('gateway', '')!r}"
        )
    return mismatches


def _node_network_attachments(
    node: DeploymentNodeRealization,
) -> tuple[DeploymentNetworkAttachment, ...]:
    """Return explicit attachments, falling back to legacy network names."""

    if node.network_attachments:
        return node.network_attachments
    return tuple(
        DeploymentNetworkAttachment(network=network)
        for network in node.networks
    )


def _node_network_aliases(node: DeploymentNodeRealization) -> tuple[str, ...]:
    """Return stable DNS aliases to preserve on manual Docker connects."""

    return tuple(
        dict.fromkeys(
            alias
            for alias in (node.service_name, node.name)
            if alias
        )
    )


class ComposeRealizationMixin:
    """Realize typed scenario specs through Docker Compose network membership."""

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose."""

        profiles = list(realization.profiles)
        image_result, compose_files = self._prepare_realization_images(realization)
        result = image_result
        if result is None:
            network_failures = self._ensure_realization_networks(realization)
            result = (
                LabResult(success=False, error="; ".join(network_failures[:5]))
                if network_failures
                else None
            )
        if result is None:
            start_result = self._start_realized_services(
                profiles,
                build=build,
                compose_files=compose_files,
            )
            result = self._realization_result(start_result, realization)
        return result

    def _prepare_realization_images(
        self,
        realization: DeploymentRealizationSpec,
    ) -> tuple[LabResult | None, tuple[Path, ...] | None]:
        """Run typed pull/build image operations and write a compose override."""

        if not realization.images:
            return None, None
        for image in realization.images:
            result = self._realize_image(image)
            if result is not None:
                return result, None
        override_path = self._write_image_override(realization.images)
        return None, (self._project_dir / "docker-compose.yml", override_path)

    def _realize_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Run one image operation through this backend's Docker runner."""

        if image.mode == "pull":
            return self._pull_realization_image(image)
        if image.mode == "build":
            return self._build_realization_image(image)
        return LabResult(
            success=False,
            error=f"Unsupported image realization mode for ACES node {image.address}.",
        )

    def _pull_realization_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Pull one scenario-resolved image reference."""

        result = self._run(
            ["docker", "pull", image.image_ref],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        error = (
            f"Image pull failed for ACES node {image.address}."
            if result.returncode != 0
            else None
        )
        return LabResult(success=False, error=error) if error else None

    def _build_realization_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Build one scenario-resolved local image reference."""

        error = self._build_realization_input_error(image)
        if error is None:
            result = self._run(
                [
                    "docker",
                    "build",
                    "-t",
                    image.image_ref,
                    "-f",
                    str(image.dockerfile_path),
                    str(image.context_path),
                ],
                timeout=_IMAGE_REALIZATION_TIMEOUT,
            )
            error = (
                f"Image build failed for ACES node {image.address}."
                if result.returncode != 0
                else None
            )
        return LabResult(success=False, error=error) if error else None

    @staticmethod
    def _build_realization_input_error(
        image: DeploymentImageRealization,
    ) -> str | None:
        """Return an image-build input error message, if any."""

        return (
            f"Image build input missing for ACES node {image.address}."
            if not image.dockerfile_path or not image.context_path
            else None
        )

    def _write_image_override(
        self,
        images: tuple[DeploymentImageRealization, ...],
    ) -> Path:
        """Write a contained Compose override for scenario-resolved images."""

        override_path = self._project_dir / _IMAGE_OVERRIDE_RELATIVE_PATH
        override_path.parent.mkdir(parents=True, exist_ok=True)
        services = {
            image.service_name: {"image": image.image_ref, "build": None}
            for image in images
        }
        override_path.write_text(
            yaml.safe_dump({"services": services}, sort_keys=True),
            encoding="utf-8",
        )
        return override_path

    def _start_with_compose_files(
        self,
        profiles: list[str],
        *,
        build: bool,
        compose_files: tuple[Path, ...],
    ) -> LabResult:
        """Start lab services using a generated realization override."""

        cmd = self._build_command("up", profiles, compose_files=compose_files)
        if build:
            cmd.append("--build")
        cmd.append("-d")
        result = self._run(cmd)
        if result.returncode != 0:
            return LabResult(success=False, error=result.stderr)
        return LabResult(success=True, message="Lab started")

    def _start_realized_services(
        self,
        profiles: list[str],
        *,
        build: bool,
        compose_files: tuple[Path, ...] | None,
    ) -> LabResult:
        """Start services with the generated override when one exists."""

        if compose_files is None:
            return self.start(profiles, build=build)
        return self._start_with_compose_files(
            profiles,
            build=build,
            compose_files=compose_files,
        )

    def _realization_result(
        self,
        start_result: LabResult,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Return the final result after service start and network reconciliation."""

        result = start_result
        if start_result.success:
            failures = self._reconcile_realization_networks(realization)
            result = (
                LabResult(success=False, error="; ".join(failures[:5]))
                if failures
                else LabResult(success=True, message="Lab realized")
            )
        return result

    def _ensure_realization_networks(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Create scenario-declared project networks that do not exist."""

        if not realization.networks:
            return []
        managed_networks = set(self.host_list_lab_networks(self._project_name))
        failures: list[str] = []
        for network in realization.networks:
            match = _match_managed_network(
                network.name,
                managed_networks,
                self._project_name,
            )
            if match is not None:
                failures.extend(
                    self._realization_network_reuse_failures(match, network)
                )
                continue
            result = self.create_network(network)
            if result.success:
                managed_networks.add(
                    _concrete_network_name(network.name, self._project_name)
                )
            else:
                failures.append(
                    result.error
                    or f"Failed to create realized network {network.name}."
                )
        return failures

    def _realization_network_reuse_failures(
        self,
        network_name: str,
        network: DeploymentNetworkRealization,
    ) -> list[str]:
        """Return fail-closed errors for an existing realized network."""

        compose_key = _compose_network_key(network.name)
        if not compose_key:
            return ["Invalid network realization name."]
        details = self.host_inspect_network(network_name)
        if not details:
            return [
                f"Existing network {network_name} was not inspectable "
                f"for realized network {network.name}."
            ]

        labels = details.get("labels")
        if not isinstance(labels, dict):
            labels = {}
        mismatches = _network_policy_mismatches(
            details,
            labels,
            network,
            project_name=self._project_name,
            compose_key=compose_key,
        )
        return [
            f"Existing network {network_name} does not match realized "
            f"network {network.name}: {mismatch}."
            for mismatch in mismatches
        ]

    def _reconcile_realization_networks(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Align realized containers with the scenario-declared networks."""

        managed_networks = set(self.host_list_lab_networks(self._project_name))
        if not managed_networks:
            return ["APTL managed networks were not visible after startup."]

        failures: list[str] = []
        for node in realization.nodes:
            if not node.container_name or not node.networks:
                continue
            desired, missing = _resolve_realization_network_attachments(
                _node_network_attachments(node),
                managed_networks,
                self._project_name,
            )
            if missing:
                failures.append(
                    "No managed Docker network matched ACES network(s) "
                    f"{', '.join(missing)} for node {node.name}."
                )
                continue
            info = self.container_inspect(node.container_name)
            if not info:
                failures.append(
                    f"Container {node.container_name} was not inspectable "
                    f"for realized node {node.name}."
                )
                continue
            current = _container_networks(info) & managed_networks
            aliases = _node_network_aliases(node)
            reattach, reattach_failures = self._reconnect_static_ip_drifts(
                node.container_name,
                info,
                desired,
                aliases,
            )
            failures.extend(reattach_failures)
            current = current - set(reattach)
            failures.extend(
                self._disconnect_extra_networks(
                    node.container_name,
                    current,
                    set(desired),
                )
            )
            failures.extend(
                self._connect_missing_networks(
                    node.container_name,
                    current,
                    desired,
                    aliases,
                )
            )
        return failures

    def _reconnect_static_ip_drifts(
        self,
        container_name: str,
        info: dict[str, Any],
        desired: dict[str, DeploymentNetworkAttachment],
        aliases: tuple[str, ...],
    ) -> tuple[list[str], list[str]]:
        """Disconnect already-attached networks whose static IP is wrong."""

        reattach: list[str] = []
        failures: list[str] = []
        for network_name, attachment in desired.items():
            if not attachment.ipv4_address:
                continue
            current_ip = _container_network_ip(info, network_name)
            if current_ip and current_ip != attachment.ipv4_address:
                result = self.disconnect_container_network(container_name, network_name)
                if result.success:
                    reattach.append(network_name)
                else:
                    failures.append(
                        result.error
                        or (
                            f"Failed to disconnect {container_name} "
                            f"from {network_name}."
                        )
                    )
        return reattach, failures

    def _disconnect_extra_networks(
        self,
        container_name: str,
        current: set[str],
        desired: set[str],
    ) -> list[str]:
        """Detach a realized container from project networks outside its spec."""

        failures: list[str] = []
        for network_name in sorted(current - desired):
            result = self.disconnect_container_network(container_name, network_name)
            if not result.success:
                failures.append(
                    result.error
                    or f"Failed to disconnect {container_name} from {network_name}."
                )
        return failures

    def _connect_missing_networks(
        self,
        container_name: str,
        current: set[str],
        desired: dict[str, DeploymentNetworkAttachment],
        aliases: tuple[str, ...],
    ) -> list[str]:
        """Attach a realized container to declared project networks it lacks."""

        failures: list[str] = []
        for network_name in sorted(set(desired) - current):
            attachment = desired[network_name]
            result = self.connect_container_network(
                container_name,
                network_name,
                ipv4_address=attachment.ipv4_address,
                aliases=aliases,
            )
            if not result.success:
                failures.append(
                    result.error
                    or f"Failed to connect {container_name} to {network_name}."
                )
        return failures

    def create_network(self, network: DeploymentNetworkRealization) -> LabResult:
        """Create one project-scoped Docker bridge network."""

        concrete_name = _concrete_network_name(network.name, self._project_name)
        compose_key = _compose_network_key(network.name)
        if not concrete_name or not compose_key:
            return LabResult(success=False, error="Invalid network realization name.")
        cmd = [
            "docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            f"{_COMPOSE_PROJECT_LABEL}={self._project_name}",
            "--label",
            f"{_COMPOSE_NETWORK_LABEL}={compose_key}",
            "--label",
            f"{_REALIZATION_NETWORK_LABEL}={_REALIZATION_NETWORK_LABEL_VALUE}",
        ]
        if network.internal is True:
            cmd.append("--internal")
        if network.cidr:
            cmd.extend(["--subnet", network.cidr])
        if network.gateway:
            cmd.extend(["--gateway", network.gateway])
        cmd.append(concrete_name)
        result = self._run(cmd, timeout=_REALIZATION_TIMEOUT)
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=(
                    f"Failed to create realized network {network.name}: "
                    f"{result.stderr.strip()}"
                ),
            )
        return LabResult(success=True, message=concrete_name)

    def connect_container_network(
        self,
        container_name: str,
        network_name: str,
        *,
        ipv4_address: str | None = None,
        aliases: tuple[str, ...] = (),
    ) -> LabResult:
        """Connect one container to one Docker network."""

        cmd = ["docker", "network", "connect"]
        if ipv4_address:
            cmd.extend(["--ip", ipv4_address])
        for alias in dict.fromkeys(alias for alias in aliases if alias):
            cmd.extend(["--alias", alias])
        cmd.extend([network_name, container_name])
        result = self._run(cmd, timeout=_REALIZATION_TIMEOUT)
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=(
                    f"Failed to connect {container_name} to {network_name}: "
                    f"{result.stderr.strip()}"
                ),
            )
        return LabResult(success=True, message="connected")

    def disconnect_container_network(
        self,
        container_name: str,
        network_name: str,
    ) -> LabResult:
        """Disconnect one container from one Docker network."""

        result = self._run(
            ["docker", "network", "disconnect", network_name, container_name],
            timeout=_REALIZATION_TIMEOUT,
        )
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=(
                    f"Failed to disconnect {container_name} from {network_name}: "
                    f"{result.stderr.strip()}"
                ),
            )
        return LabResult(success=True, message="disconnected")

    def remove_project_networks(self) -> list[str]:
        """Remove leftover project-scoped realization networks."""

        failures: list[str] = []
        try:
            result = self._run(
                [
                    "docker",
                    "network",
                    "ls",
                    "--filter",
                    f"label={_COMPOSE_PROJECT_LABEL}={self._project_name}",
                    "--filter",
                    (
                        f"label={_REALIZATION_NETWORK_LABEL}="
                        f"{_REALIZATION_NETWORK_LABEL_VALUE}"
                    ),
                    "--filter",
                    f"name={self._project_name}",
                    "--format",
                    "{{.Name}}",
                ],
                timeout=_REALIZATION_TIMEOUT,
            )
        except (BackendTimeoutError, OSError) as exc:
            return [f"Failed to list project networks for cleanup: {exc}"]
        if result.returncode != 0:
            return [
                "Failed to list project networks for cleanup: "
                f"{result.stderr.strip()}"
            ]
        network_names = [
            line.strip() for line in result.stdout.splitlines() if line.strip()
        ]
        for network_name in network_names:
            try:
                result = self._run(
                    ["docker", "network", "rm", network_name],
                    timeout=_REALIZATION_TIMEOUT,
                )
            except (BackendTimeoutError, OSError) as exc:
                failures.append(
                    f"Failed to remove project network {network_name}: {exc}"
                )
                continue
            if result.returncode != 0:
                failures.append(
                    f"Failed to remove project network {network_name}: "
                    f"{result.stderr.strip()}"
                )
        return failures
