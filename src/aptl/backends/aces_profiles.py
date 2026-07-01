"""Compose profile mapping for the APTL ACES backend."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import re

import yaml

from aptl.core.config import AptlConfig

CORE_PROFILES = ("otel",)
IDENTIFIER_SEPARATORS = re.compile(r"[^a-z0-9]+")
APTL_SERVICE_ALIASES = {
    "db": frozenset({"customer-db", "postgres"}),
    "kali": frozenset({"red-workbench"}),
    "webapp": frozenset({"customer-portal", "customer-portal-app"}),
    "wazuh.indexer": frozenset({"wazuh-indexer"}),
    "wazuh.manager": frozenset({"wazuh-manager"}),
}


@dataclass(frozen=True)
class ComposeServiceInfo(object):
    """APTL-relevant metadata for one Compose service."""

    name: str
    aliases: frozenset[str]
    profiles: frozenset[str]
    dependencies: frozenset[str]
    networks: frozenset[str]
    container_name: str | None
    network_addresses: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ComposeProfileIndex(object):
    """Compose service aliases indexed to profile names and dependencies."""

    alias_to_profiles: dict[str, frozenset[str]]
    alias_to_services: dict[str, frozenset[str]]
    services: dict[str, ComposeServiceInfo]

    def profiles_for_aliases(self, aliases: set[str]) -> frozenset[str]:
        """Return all profiles associated with any normalized alias."""
        profiles: set[str] = set()
        for alias in aliases:
            profiles.update(self.alias_to_profiles.get(alias, frozenset()))
        return frozenset(profiles)

    def service_names_for_aliases(self, aliases: set[str]) -> frozenset[str]:
        """Return Compose service names associated with normalized aliases."""
        unique_services: set[str] = set()
        services: set[str] = set()
        for alias in aliases:
            matches = self.alias_to_services.get(alias, frozenset())
            if len(matches) == 1:
                unique_services.update(matches)
            services.update(matches)
        if unique_services:
            return frozenset(unique_services)
        return frozenset(services)

    def profiles_for_services(self, service_names: set[str]) -> frozenset[str]:
        """Return all profiles for the named Compose services."""
        profiles: set[str] = set()
        for service_name in service_names:
            service = self.services.get(service_name)
            if service is not None:
                profiles.update(service.profiles)
        return frozenset(profiles)

    def network_aliases(self) -> frozenset[str]:
        """Return normalized Compose network aliases used by indexed services."""
        aliases: set[str] = set()
        for service in self.services.values():
            for network_name in service.networks:
                aliases.update(normalized_identifier_aliases(network_name))
        return frozenset(aliases)

    def dependency_closure_for_services(
        self, service_names: set[str]
    ) -> tuple[frozenset[str], dict[str, tuple[str, ...]]]:
        """Return transitive Compose ``depends_on`` closure and missing edges."""
        closure = set(service_names)
        pending = list(service_names)
        missing: dict[str, set[str]] = {}
        while pending:
            service_name = pending.pop()
            service = self.services.get(service_name)
            if service is None:
                continue
            for dependency in service.dependencies:
                if dependency not in self.services:
                    missing.setdefault(service_name, set()).add(dependency)
                    continue
                if dependency not in closure:
                    closure.add(dependency)
                    pending.append(dependency)
        return (
            frozenset(closure),
            {
                service_name: tuple(sorted(dependencies))
                for service_name, dependencies in missing.items()
            },
        )

    def _service_active(self, service_name: str, selected_profiles: set[str]) -> bool:
        """Return whether a Compose service runs under the selected profiles."""
        service = self.services.get(service_name)
        if service is None:
            return False
        # A service with no profiles is always active; otherwise it runs when
        # it shares at least one profile with the selection. This mirrors
        # `docker compose --profile` activation semantics.
        return (not service.profiles) or bool(service.profiles & selected_profiles)

    def cross_profile_dependency_gaps(
        self, selected_profiles: set[str]
    ) -> dict[str, tuple[str, ...]]:
        """Return active services whose ``depends_on`` targets are inactive.

        ``docker compose --profile`` activates every service in a selected
        profile, not just the ACES nodes a scenario declares. When an activated
        service depends on a known service that the profile selection excludes,
        Compose rejects the project ("depends on undefined service"). This is
        invisible to node-level realization, so it is checked here against the
        full Compose service graph for the selected profiles.
        """
        selected = set(selected_profiles)
        gaps: dict[str, set[str]] = {}
        for service_name, service in self.services.items():
            if not self._service_active(service_name, selected):
                continue
            for dependency in service.dependencies:
                # Unknown dependencies are reported by the dependency-closure
                # pass; here we only flag known services excluded by the
                # profile selection.
                if dependency not in self.services:
                    continue
                if not self._service_active(dependency, selected):
                    gaps.setdefault(service_name, set()).add(dependency)
        return {
            service_name: tuple(sorted(dependencies))
            for service_name, dependencies in gaps.items()
        }


def load_compose_profile_index(project_dir: Path) -> ComposeProfileIndex:
    """Load Compose service/profile aliases from ``docker-compose.yml``."""
    services = _load_compose_services(project_dir)
    alias_to_profiles: dict[str, set[str]] = {}
    alias_to_services: dict[str, set[str]] = {}
    service_infos: dict[str, ComposeServiceInfo] = {}
    for service_name, service_def in services.items():
        info = _service_info(str(service_name), service_def)
        if info is None:
            continue
        service_infos[info.name] = info
        for alias in info.aliases:
            alias_to_services.setdefault(alias, set()).add(info.name)
            alias_to_profiles.setdefault(alias, set()).update(info.profiles)
    return ComposeProfileIndex(
        alias_to_profiles={
            alias: frozenset(profiles)
            for alias, profiles in alias_to_profiles.items()
        },
        alias_to_services={
            alias: frozenset(service_names)
            for alias, service_names in alias_to_services.items()
        },
        services=service_infos,
    )


def node_aliases(address: str, payload: Mapping[str, Any]) -> set[str]:
    """Return normalized aliases that can bind an ACES node to Compose."""
    aliases: set[str] = set()
    for value in _raw_node_values(address, payload):
        aliases.update(normalized_identifier_aliases(value))
        aliases.update(_terminal_address_aliases(value))
    return aliases


def explicit_compose_profile_hints(payload: Mapping[str, Any]) -> frozenset[str]:
    """Extract explicit APTL Compose profile hints from ACES payload data."""
    hints: set[str] = set()
    for parent in _iter_profile_hint_parents(payload):
        hints.update(profile_values(parent.get("compose_profiles")))
        hints.update(profile_values(parent.get("compose_profile")))
    return frozenset(hints)


def profile_values(raw: object) -> set[str]:
    """Normalize a scalar or iterable profile hint into strings."""
    if isinstance(raw, str):
        return {raw} if raw.strip() else set()
    if isinstance(raw, list | tuple | set | frozenset):
        return {str(value) for value in raw if str(value).strip()}
    return set()


def configured_profiles(config: AptlConfig) -> list[str]:
    """Return enabled APTL profile names from config."""
    return list(config.containers.enabled_profiles())


def public_start_profiles(config: AptlConfig) -> list[str]:
    """Return the Compose profiles used by the public lab start path."""
    selected = configured_profiles(config)
    for profile in CORE_PROFILES:
        if profile not in selected:
            selected.append(profile)
    return selected


def select_backend_profiles(
    config: AptlConfig,
    plan_profiles: frozenset[str],
) -> list[str]:
    """Intersect ACES plan profiles with enabled APTL profiles."""
    selected = [
        profile
        for profile in public_start_profiles(config)
        if profile in plan_profiles or profile in CORE_PROFILES
    ]
    return selected


def steady_state_service_aliases_for_profiles(
    project_dir: Path, selected_profiles: list[str]
) -> dict[str, tuple[str, ...]]:
    """Return normalized aliases for steady-state services in selected profiles."""
    selected = set(selected_profiles)
    services = _load_compose_services(project_dir)
    return {
        str(service_name): _normalized_service_aliases(str(service_name), service_def)
        for service_name, service_def in services.items()
        if _service_selected(service_def, selected)
    }


def normalized_identifier_aliases(raw: str) -> set[str]:
    """Return normalized aliases for one Compose or ACES identifier."""
    normalized = normalize_identifier(raw)
    if not normalized:
        return set()
    aliases = {normalized}
    if normalized.startswith("aptl-"):
        aliases.add(normalized.removeprefix("aptl-"))
    return {alias for alias in aliases if alias}


def normalize_identifier(raw: str) -> str:
    """Normalize punctuation and case for loose identifier matching."""
    lowered = raw.strip().lower()
    return IDENTIFIER_SEPARATORS.sub("-", lowered).strip("-")


def _load_compose_services(project_dir: Path) -> Mapping[str, object]:
    """Return the validated Compose services mapping."""
    compose_path = project_dir / "docker-compose.yml"
    if not compose_path.exists():
        raise ValueError(f"docker-compose.yml not found under {project_dir}")
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"{compose_path} must contain a YAML mapping")
    services = data.get("services") or {}
    if not isinstance(services, Mapping):
        raise ValueError(f"{compose_path} services section must be a mapping")
    return services


def _service_info(
    service_name: str,
    service_def: object,
) -> ComposeServiceInfo | None:
    """Return indexed metadata for one Compose service."""
    if not isinstance(service_def, Mapping):
        return None
    return ComposeServiceInfo(
        name=service_name,
        aliases=frozenset(_normalized_service_aliases(service_name, service_def)),
        profiles=frozenset(_service_profiles(service_def)),
        dependencies=frozenset(_service_dependencies(service_def)),
        networks=frozenset(_service_networks(service_def)),
        container_name=_service_container_name(service_def),
        network_addresses=_service_network_addresses(service_def),
    )


def _service_profiles(service_def: Mapping[str, object]) -> set[str]:
    """Return non-empty profile strings for a Compose service."""
    return {
        str(profile)
        for profile in (service_def.get("profiles") or [])
        if str(profile).strip()
    }


def _service_dependencies(service_def: Mapping[str, object]) -> set[str]:
    """Return service names from a Compose ``depends_on`` declaration."""
    depends_on = service_def.get("depends_on")
    if isinstance(depends_on, Mapping):
        return {str(service_name) for service_name in depends_on if str(service_name)}
    if isinstance(depends_on, list | tuple | set | frozenset):
        return {str(service_name) for service_name in depends_on if str(service_name)}
    return set()


def _service_networks(service_def: Mapping[str, object]) -> set[str]:
    """Return network names selected by a Compose service."""
    networks = service_def.get("networks")
    if isinstance(networks, Mapping):
        return {str(network_name) for network_name in networks if str(network_name)}
    if isinstance(networks, list | tuple | set | frozenset):
        return {str(network_name) for network_name in networks if str(network_name)}
    return set()


def _service_network_addresses(service_def: Mapping[str, object]) -> dict[str, str]:
    """Return static IPv4 addresses keyed by Compose network name."""

    networks = service_def.get("networks")
    if not isinstance(networks, Mapping):
        return {}
    addresses: dict[str, str] = {}
    for network_name, network_def in networks.items():
        if not isinstance(network_def, Mapping):
            continue
        address = network_def.get("ipv4_address")
        if isinstance(address, str) and address.strip():
            addresses[str(network_name)] = address
    return addresses


def _service_selected(service_def: object, selected_profiles: set[str]) -> bool:
    """Return whether a service is steady-state and in a selected profile."""
    if not isinstance(service_def, Mapping):
        return False
    profiles = _service_profiles(service_def)
    return bool(profiles & selected_profiles) and not _is_one_shot(service_def)


def _is_one_shot(service_def: Mapping[str, object]) -> bool:
    """Return whether Compose marks a service as a non-steady-state task."""
    return str(service_def.get("restart", "")).lower() in {"no", "false"}


def _normalized_service_aliases(
    service_name: str,
    service_def: object,
) -> tuple[str, ...]:
    """Return sorted normalized aliases for one Compose service."""
    if not isinstance(service_def, Mapping):
        return ()
    aliases: set[str] = set()
    for alias in _service_aliases(service_name, service_def):
        aliases.update(normalized_identifier_aliases(alias))
    return tuple(sorted(aliases))


def _service_aliases(
    service_name: str,
    service_def: Mapping[str, object],
) -> set[str]:
    """Return service name, container name, source, and hostname aliases."""
    aliases = {service_name}
    aliases.update(APTL_SERVICE_ALIASES.get(service_name, frozenset()))
    for alias_key in ("container_name", "hostname"):
        alias = service_def.get(alias_key)
        if isinstance(alias, str) and alias.strip():
            aliases.add(alias)
    aliases.update(_image_aliases(service_def))
    aliases.update(_build_aliases(service_def))
    return aliases


def _service_container_name(service_def: Mapping[str, object]) -> str | None:
    """Return the explicit Compose container name, if present."""

    value = service_def.get("container_name")
    if isinstance(value, str) and value.strip():
        return value
    return None


def _image_aliases(service_def: Mapping[str, object]) -> set[str]:
    """Return aliases derived from a Compose image reference."""

    image = service_def.get("image")
    if not isinstance(image, str) or not image.strip():
        return set()
    terminal = image.rsplit("/", 1)[-1]
    repository = terminal.split(":", 1)[0]
    aliases = {repository}
    if repository.endswith("-alpine"):
        aliases.add(repository.removesuffix("-alpine"))
    return {alias for alias in aliases if alias}


def _build_aliases(service_def: Mapping[str, object]) -> set[str]:
    """Return aliases derived from a Compose build context."""

    build = service_def.get("build")
    context: object = None
    if isinstance(build, str):
        context = build
    elif isinstance(build, Mapping):
        context = build.get("context")
    if not isinstance(context, str) or not context.strip():
        return set()
    return {Path(context).name}


def _raw_node_values(address: str, payload: Mapping[str, Any]) -> set[str]:
    """Collect raw string values that can identify an ACES node."""
    raw_values = {address}
    raw_values.update(_payload_string_values(payload, ("name", "node_name", "target_node")))
    spec = payload.get("spec")
    if isinstance(spec, Mapping):
        node_spec = spec.get("node")
        if isinstance(node_spec, Mapping):
            raw_values.update(
                _payload_string_values(node_spec, ("name", "node_id", "hostname"))
            )
            source = node_spec.get("source")
            if isinstance(source, Mapping):
                raw_values.update(_payload_string_values(source, ("name",)))
    return raw_values


def _payload_string_values(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
) -> set[str]:
    """Return non-empty string values for selected payload keys."""
    values: set[str] = set()
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            values.add(value)
    return values


def _terminal_address_aliases(raw: str) -> set[str]:
    """Return aliases from the terminal segment of dotted ACES addresses."""
    if "." not in raw:
        return set()
    return normalized_identifier_aliases(raw.rsplit(".", 1)[-1])


def _iter_profile_hint_parents(
    payload: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    """Return payload mappings that can contain APTL profile hints."""
    parents: list[Mapping[str, Any]] = []
    for parent_key in ("runtime", "aptl"):
        parent = payload.get(parent_key)
        if isinstance(parent, Mapping):
            parents.append(parent)
    spec = payload.get("spec")
    if isinstance(spec, Mapping):
        for parent_key in ("runtime", "aptl"):
            parent = spec.get(parent_key)
            if isinstance(parent, Mapping):
                parents.append(parent)
    return parents
