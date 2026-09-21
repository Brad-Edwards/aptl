"""Content-qualified image integration for generated Compose services.

The SDL owns the runtime and its generated artifacts. A pack adapter may bind
an existing project file to an additional image-specific path, or load an
existing environment file, when the upstream image cannot consume the SDL's
portable artifact location directly. No service or artifact is created here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast
import re

import yaml

from aptl.utils.pathsafe import PathContainmentError, open_contained_nofollow

from aptl.backends.scenario_startup import (
    ScenarioStartupProviderError,
    selected_runtime_provider,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)

_OVERRIDE_RELPATH = Path(".aptl/realization/compose.service.yml")
_INVALID = "provider-compose-service-result-invalid"


@dataclass(frozen=True)
class ServiceFileMount:
    """Bind an existing project file to one image-specific container path."""

    service: str
    project_file: str
    target: str


@dataclass(frozen=True)
class ServiceEnvironmentFile:
    """Load an existing project environment file for one service."""

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
    """Adapter-supplied aliases for artifacts and names already realized by SDL."""

    mounts: tuple[ServiceFileMount, ...] = ()
    environment_files: tuple[ServiceEnvironmentFile, ...] = ()
    container_name_environment: tuple[ServiceContainerNameEnvironment, ...] = ()


def _project_file(root: Path, name: str) -> Path:
    """Resolve an existing project-relative file without leaving the project."""

    path = Path(name)
    if (
        not name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ScenarioStartupProviderError(_INVALID)
    resolved_root = root.resolve()
    try:
        with open_contained_nofollow(resolved_root, name):
            pass  # NOSONAR
    except PathContainmentError as exc:
        raise ScenarioStartupProviderError(_INVALID) from exc
    return resolved_root / path


def _target(value: str) -> str:
    """Require a normalized absolute container target path."""

    path = PurePosixPath(value)
    if not value or not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ScenarioStartupProviderError(_INVALID)
    return value


def certificate_mount_aliases(
    spec: DeploymentRealizationSpec,
    root: Path,
    expected: dict[str, set[tuple[str, str]]],
) -> dict[str, set[tuple[str, str]]]:
    """Authorize only exact adapter aliases of SDL-owned cert sources.

    This is consumed by effective-model validation independently of the
    generated override. An edited Compose file cannot authorize itself.
    """

    provider = selected_runtime_provider(spec.pack_identity, spec.startup_selection)
    resolver = getattr(provider, "compose_service_policy", None) if provider else None
    if resolver is None:
        return {}
    if not callable(resolver):
        raise ScenarioStartupProviderError(_INVALID)
    policy = resolver()
    if not isinstance(policy, ScenarioComposeServicePolicy):
        raise ScenarioStartupProviderError(_INVALID)
    aliases: dict[str, set[tuple[str, str]]] = {}
    for mount in policy.mounts:
        if not isinstance(mount, ServiceFileMount):
            raise ScenarioStartupProviderError(_INVALID)
        source = str(_project_file(root, mount.project_file))
        authored_sources = {item[0] for item in expected.get(mount.service, set())}
        if source in authored_sources:
            aliases.setdefault(mount.service, set()).add(
                (source, _target(mount.target))
            )
    return aliases


def _active_nodes(
    spec: DeploymentRealizationSpec,
) -> dict[str, DeploymentNodeRealization]:
    """Select only service nodes whose image was emitted by realization."""

    emitted = {image.address for image in spec.images}
    return {
        node.service_name: node
        for node in spec.nodes
        if node.service_name and node.address in emitted
    }


def _append_mounts(
    policy: ScenarioComposeServicePolicy,
    nodes: dict[str, DeploymentNodeRealization],
    root: Path,
    services: dict[str, dict[str, object]],
) -> None:
    """Add non-duplicating aliases of existing project files to live services."""

    targets: set[tuple[str, str]] = set()
    for mount in policy.mounts:
        if not isinstance(mount, ServiceFileMount) or mount.service not in nodes:
            raise ScenarioStartupProviderError(_INVALID)
        target = _target(mount.target)
        pair = (mount.service, target)
        authored_targets = {
            item.target for item in getattr(nodes[mount.service].runtime, "mounts", ())
        }
        if pair in targets or target in authored_targets:
            raise ScenarioStartupProviderError(_INVALID)
        targets.add(pair)
        volumes = cast(
            list[dict[str, object]],
            services.setdefault(mount.service, {}).setdefault("volumes", []),
        )
        volumes.append(
            {
                "type": "bind",
                "source": str(_project_file(root, mount.project_file)),
                "target": target,
                "read_only": True,
            }
        )


def _append_environment_files(
    policy: ScenarioComposeServicePolicy,
    nodes: dict[str, DeploymentNodeRealization],
    root: Path,
    services: dict[str, dict[str, object]],
) -> None:
    """Add each existing environment file at most once per live service."""

    seen: set[tuple[str, str]] = set()
    for item in policy.environment_files:
        if not isinstance(item, ServiceEnvironmentFile) or item.service not in nodes:
            raise ScenarioStartupProviderError(_INVALID)
        source = str(_project_file(root, item.project_file))
        pair = (item.service, source)
        if pair in seen:
            raise ScenarioStartupProviderError(_INVALID)
        seen.add(pair)
        env_files = cast(
            list[str], services.setdefault(item.service, {}).setdefault("env_file", [])
        )
        env_files.append(source)


def _container_name_binding(
    item: ServiceContainerNameEnvironment,
    nodes: dict[str, DeploymentNodeRealization],
    container_name_for_semantic: Callable[[str], str] | None,
) -> tuple[str, str, str]:
    """Validate one name binding against realized and SDL-authored values."""

    if (
        not isinstance(item, ServiceContainerNameEnvironment)
        or item.service not in nodes
        or item.target_service not in nodes
        or not re.fullmatch(r"[A-Z][A-Z0-9_]*", item.variable)
        or container_name_for_semantic is None
    ):
        raise ScenarioStartupProviderError(_INVALID)
    authored_names = {
        variable.name
        for variable in getattr(nodes[item.service].runtime, "environment", ())
    }
    if item.variable in authored_names:
        raise ScenarioStartupProviderError(_INVALID)
    target = nodes[item.target_service]
    semantic_name = target.container_name or f"aptl-{target.name}"
    return item.service, item.variable, container_name_for_semantic(semantic_name)


def _append_container_names(
    policy: ScenarioComposeServicePolicy,
    nodes: dict[str, DeploymentNodeRealization],
    services: dict[str, dict[str, object]],
    container_name_for_semantic: Callable[[str], str] | None,
) -> None:
    """Add unique image-required container names without changing SDL names."""

    seen: set[tuple[str, str]] = set()
    for item in policy.container_name_environment:
        service, variable, name = _container_name_binding(
            item, nodes, container_name_for_semantic
        )
        pair = (service, variable)
        if pair in seen:
            raise ScenarioStartupProviderError(_INVALID)
        seen.add(pair)
        environment = cast(
            dict[str, str],
            services.setdefault(service, {}).setdefault("environment", {}),
        )
        environment[variable] = name


def _resolved_services(
    spec: DeploymentRealizationSpec,
    root: Path,
    *,
    container_name_for_semantic: Callable[[str], str] | None = None,
) -> dict[str, dict[str, object]]:
    """Resolve the adapter policy into an additional, bounded Compose overlay."""

    provider = selected_runtime_provider(spec.pack_identity, spec.startup_selection)
    resolver = getattr(provider, "compose_service_policy", None) if provider else None
    if resolver is None:
        return {}
    if not callable(resolver):
        raise ScenarioStartupProviderError(_INVALID)
    try:
        policy = resolver()
        if not isinstance(policy, ScenarioComposeServicePolicy):
            raise ScenarioStartupProviderError(_INVALID)
        nodes = _active_nodes(spec)
        services: dict[str, dict[str, object]] = {}
        _append_mounts(policy, nodes, root, services)
        _append_environment_files(policy, nodes, root, services)
        _append_container_names(policy, nodes, services, container_name_for_semantic)
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
    """Write only adapter-authorized additions to the generated Compose model."""

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
