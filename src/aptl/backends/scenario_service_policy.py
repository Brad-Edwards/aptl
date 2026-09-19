"""Content-qualified image integration for generated Compose services.

The SDL owns the runtime and its generated artifacts. A pack adapter may bind
an existing project file to an additional image-specific path, or load an
existing environment file, when the upstream image cannot consume the SDL's
portable artifact location directly. No service or artifact is created here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from collections.abc import Callable
import re

import yaml

from aptl.backends.scenario_startup import (
    ScenarioStartupProviderError,
    _runtime_provider,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec

_OVERRIDE_RELPATH = Path(".aptl/realization/compose.service.yml")
_INVALID = "provider-compose-service-result-invalid"


@dataclass(frozen=True)
class ServiceFileMount:
    service: str
    project_file: str
    target: str


@dataclass(frozen=True)
class ServiceEnvironmentFile:
    service: str
    project_file: str


@dataclass(frozen=True)
class ServiceContainerNameEnvironment:
    """Pass a realized container name to an image that spawns child containers."""

    service: str
    variable: str
    target_service: str


@dataclass(frozen=True)
class ScenarioComposeServicePolicy:
    mounts: tuple[ServiceFileMount, ...] = ()
    environment_files: tuple[ServiceEnvironmentFile, ...] = ()
    container_name_environment: tuple[ServiceContainerNameEnvironment, ...] = ()


def _project_file(root: Path, name: str) -> Path:
    path = Path(name)
    if (
        not name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ScenarioStartupProviderError(_INVALID)
    resolved_root = root.resolve()
    resolved = (resolved_root / path).resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ScenarioStartupProviderError(_INVALID)
    return resolved


def _target(value: str) -> str:
    path = PurePosixPath(value)
    if not value or not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ScenarioStartupProviderError(_INVALID)
    return value


def _resolved_services(
    spec: DeploymentRealizationSpec,
    root: Path,
    *,
    container_name_for_semantic: Callable[[str], str] | None = None,
) -> dict[str, dict[str, object]]:
    provider = _runtime_provider(spec.pack_identity)
    resolver = getattr(provider, "compose_service_policy", None) if provider else None
    if resolver is None:
        return {}
    if not callable(resolver):
        raise ScenarioStartupProviderError(_INVALID)
    try:
        policy = resolver()
        if not isinstance(policy, ScenarioComposeServicePolicy):
            raise ScenarioStartupProviderError(_INVALID)
        emitted = {image.address for image in spec.images}
        nodes = {
            node.service_name: node
            for node in spec.nodes
            if node.service_name and node.address in emitted
        }
        services: dict[str, dict[str, object]] = {}
        targets: set[tuple[str, str]] = set()
        env_files: set[tuple[str, str]] = set()
        for mount in policy.mounts:
            if not isinstance(mount, ServiceFileMount) or mount.service not in nodes:
                raise ScenarioStartupProviderError(_INVALID)
            target = _target(mount.target)
            pair = (mount.service, target)
            authored_targets = {
                item.target
                for item in getattr(nodes[mount.service].runtime, "mounts", ())
            }
            if pair in targets or target in authored_targets:
                raise ScenarioStartupProviderError(_INVALID)
            targets.add(pair)
            services.setdefault(mount.service, {}).setdefault("volumes", []).append(
                {
                    "type": "bind",
                    "source": str(_project_file(root, mount.project_file)),
                    "target": target,
                    "read_only": True,
                }
            )
        for item in policy.environment_files:
            if (
                not isinstance(item, ServiceEnvironmentFile)
                or item.service not in nodes
            ):
                raise ScenarioStartupProviderError(_INVALID)
            source = str(_project_file(root, item.project_file))
            pair = (item.service, source)
            if pair in env_files:
                raise ScenarioStartupProviderError(_INVALID)
            env_files.add(pair)
            services.setdefault(item.service, {}).setdefault("env_file", []).append(
                source
            )
        variables: set[tuple[str, str]] = set()
        for item in policy.container_name_environment:
            if (
                not isinstance(item, ServiceContainerNameEnvironment)
                or item.service not in nodes
                or item.target_service not in nodes
                or not re.fullmatch(r"[A-Z][A-Z0-9_]*", item.variable)
                or container_name_for_semantic is None
            ):
                raise ScenarioStartupProviderError(_INVALID)
            pair = (item.service, item.variable)
            authored_names = {
                variable.name
                for variable in getattr(nodes[item.service].runtime, "environment", ())
            }
            if pair in variables or item.variable in authored_names:
                raise ScenarioStartupProviderError(_INVALID)
            variables.add(pair)
            target = nodes[item.target_service]
            semantic_name = target.container_name or f"aptl-{target.name}"
            services.setdefault(item.service, {}).setdefault("environment", {})[
                item.variable
            ] = container_name_for_semantic(semantic_name)
        return services
    except ScenarioStartupProviderError:
        raise
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScenarioStartupProviderError(_INVALID) from exc


def write_scenario_service_override(
    spec: DeploymentRealizationSpec,
    realization_root: Path,
    *,
    container_name_for_semantic: Callable[[str], str] | None = None,
) -> Path | None:
    services = _resolved_services(
        spec,
        realization_root,
        container_name_for_semantic=container_name_for_semantic,
    )
    if not services:
        return None
    path = realization_root / _OVERRIDE_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"services": services}, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    return path
