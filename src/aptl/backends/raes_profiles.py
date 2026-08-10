"""Compose profile mapping for the APTL RAES backend."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from aptl.backends._compose_profile_index import (
    ComposeProfileIndex,
    ComposeServiceInfo,
    normalize_identifier,
    normalized_identifier_aliases,
)
from aptl.core.config import AptlConfig, ContainerSettings

CORE_PROFILES = ("otel",)
# The finite vocabulary a deployment-serving provider may assign. Container
# toggles and backend-owned always-on profiles are the only authorities; the
# separate web lifecycle is intentionally absent.
OPERATOR_GROUP_VOCABULARY = tuple((*ContainerSettings.model_fields, *CORE_PROFILES))
# Legacy in-tree fallback ONLY (issue #875, SDL-authority class). These map
# older in-tree scenario node names to their docker-compose service names so
# node->service binding resolves for the legacy compose path. An env-pack never
# reaches here: it ships no docker-compose.yml, so load_compose_profile_index
# returns an empty index (ADR-048) and node service identity is derived from the
# realization DTOs. This table is never the primary decision source and retires
# with the in-tree docker-compose.yml (task #8); it is not extended.
APTL_SERVICE_ALIASES = {
    "db": frozenset({"customer-db", "postgres"}),
    "kali": frozenset({"red-workbench"}),
    "webapp": frozenset({"customer-portal", "customer-portal-app"}),
    "wazuh.indexer": frozenset({"wazuh-indexer"}),
    "wazuh.manager": frozenset({"wazuh-manager"}),
}


def load_compose_profile_index(project_dir: Path) -> ComposeProfileIndex:
    """Load Compose service/profile aliases from ``docker-compose.yml``."""
    services = _load_compose_services(project_dir)
    alias_to_profiles: dict[str, set[str]] = {}
    alias_to_services: dict[str, set[str]] = {}
    identity_aliases: dict[str, set[str]] = {}
    source_aliases: dict[str, frozenset[str]] = {}
    service_infos: dict[str, ComposeServiceInfo] = {}
    for service_name, service_def in services.items():
        info = _service_info(str(service_name), service_def)
        if info is None:
            continue
        service_infos[info.name] = info
        for alias in _identity_aliases(str(service_name), service_def):
            identity_aliases.setdefault(alias, set()).add(info.name)
        source_aliases[info.name] = _source_aliases(service_def)
        for alias in info.aliases:
            alias_to_services.setdefault(alias, set()).add(info.name)
            alias_to_profiles.setdefault(alias, set()).update(info.profiles)
    _prune_source_only_aliases(
        alias_to_services,
        alias_to_profiles,
        identity_aliases=identity_aliases,
        source_aliases=source_aliases,
        service_infos=service_infos,
    )
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


def _prune_source_only_aliases(
    alias_to_services: dict[str, set[str]],
    alias_to_profiles: dict[str, set[str]],
    *,
    identity_aliases: dict[str, set[str]],
    source_aliases: dict[str, frozenset[str]],
    service_infos: dict[str, ComposeServiceInfo],
) -> None:
    """Drop source-only claimants from an alias a real service actually names.

    An alias derived from a service's *source* — its image repository or its
    build-context directory — records where the image came from, not which
    service this is. Two services may share one build context (webapp-proxy and
    kali-ssh-proxy both build ./containers/kali-ssh-proxy), so that directory
    name is not evidence about either one.

    When some service is actually *named* by that alias, its claim wins and the
    source-only claimants drop out. Without this, declaring a node named after
    the shared context left it ambiguous against a service it has nothing to do
    with, and the node could not be realized at all.

    Deliberately narrow: only source-derived claims yield. A name-derived alias
    (a service key, or the same name with APTL's prefix stripped) still collides
    normally, so a genuinely ambiguous dependency is still rejected rather than
    silently resolved to one of the candidates.
    """

    for alias, owners in identity_aliases.items():
        claimants = alias_to_services.get(alias)
        if claimants is None or claimants <= owners:
            continue
        surviving = {
            name
            for name in claimants
            if name in owners or alias not in source_aliases.get(name, frozenset())
        }
        if surviving and surviving != claimants:
            alias_to_services[alias] = surviving
            alias_to_profiles[alias] = _profiles_for_names(surviving, service_infos)


def _profiles_for_names(
    names: set[str], service_infos: dict[str, ComposeServiceInfo]
) -> set[str]:
    """Return every profile declared by the named indexed services."""
    return {profile for name in names for profile in service_infos[name].profiles}


def node_aliases(address: str, payload: Mapping[str, Any]) -> set[str]:
    """Return normalized aliases that can bind a RAES node to Compose."""
    aliases: set[str] = set()
    for value in _raw_node_values(address, payload):
        aliases.update(normalized_identifier_aliases(value))
        aliases.update(_terminal_address_aliases(value))
    return aliases


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
    """Intersect RAES plan profiles with enabled APTL profiles."""
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


def _load_compose_services(project_dir: Path) -> Mapping[str, object]:
    """Return the validated Compose services mapping.

    ADR-048: an absent ``docker-compose.yml`` is not an error. An image-free
    scenario has no compose file, and its nodes realize from declared desired
    state, so the profile index is simply empty. A legacy scenario ships its
    compose file, so it is unaffected.
    """
    compose_path = project_dir / "docker-compose.yml"
    if not compose_path.exists():
        return {}
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
    """Return whether Compose marks a service as a non-steady-state task.

    ADR-088 (issue #889) retired the env-pack-declared TechVault operational
    scenario's only one-shot (the Cortex Elasticsearch index initializer,
    replaced by the native service-search-index-schema materializer), but the
    legacy in-tree ``docker-compose.yml`` still declares a real
    ``cortex-index-init`` one-shot service (``restart: "no"``) that
    ``scripts/cortex-apikey.sh`` and the static gate's steady-state parity
    checks (``test_techvault_static_gate.py``) still depend on. This stays until
    that legacy stack is retired too.
    """
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


def _identity_aliases(service_name: str, service_def: Mapping[str, object]) -> set[str]:
    """Return the aliases that actually name this service.

    These are the names Compose gives one specific service — its key, its
    container name, its hostname, and APTL's curated equivalents. Unlike aliases
    derived from an image repository or a build context, they cannot be shared
    with another service, so they stay authoritative even when a source alias
    has to be pruned for ambiguity.
    """

    aliases = {service_name}
    aliases.update(APTL_SERVICE_ALIASES.get(service_name, frozenset()))
    for alias_key in ("container_name", "hostname"):
        value = service_def.get(alias_key)
        if isinstance(value, str) and value.strip():
            aliases.add(value)
    return {alias for alias in map(normalize_identifier, aliases) if alias}


def _source_aliases(service_def: Mapping[str, object]) -> frozenset[str]:
    """Return aliases that describe where a service's image came from.

    An image repository or a build-context directory can be shared by several
    services, so these names are provenance rather than identity and must yield
    to a service that is genuinely named by them.
    """

    raw = _image_aliases(service_def) | _build_aliases(service_def)
    return frozenset(alias for alias in map(normalize_identifier, raw) if alias)


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
    """Collect raw string values that can identify a RAES node."""
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
    """Return aliases from the terminal segment of dotted RAES addresses."""
    if "." not in raw:
        return set()
    return normalized_identifier_aliases(raw.rsplit(".", 1)[-1])
