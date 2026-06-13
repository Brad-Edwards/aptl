"""Compose profile mapping for the APTL ACES backend."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re

import yaml

from aptl.core.config import AptlConfig

CORE_PROFILES = frozenset({"otel"})
IDENTIFIER_SEPARATORS = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class ComposeProfileIndex(object):
    """Compose service aliases indexed to profile names."""

    alias_to_profiles: dict[str, frozenset[str]]

    def profiles_for_aliases(self, aliases: set[str]) -> frozenset[str]:
        """Return all profiles associated with any normalized alias."""
        profiles: set[str] = set()
        for alias in aliases:
            profiles.update(self.alias_to_profiles.get(alias, frozenset()))
        return frozenset(profiles)


def load_compose_profile_index(project_dir: Path) -> ComposeProfileIndex:
    """Load Compose service/profile aliases from ``docker-compose.yml``."""
    services = _load_compose_services(project_dir)
    alias_to_profiles: dict[str, set[str]] = {}
    for service_name, service_def in services.items():
        _register_service_profiles(alias_to_profiles, str(service_name), service_def)
    return ComposeProfileIndex(
        {
            alias: frozenset(profiles)
            for alias, profiles in alias_to_profiles.items()
        }
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


def select_backend_profiles(
    config: AptlConfig,
    plan_profiles: frozenset[str],
) -> list[str]:
    """Intersect ACES plan profiles with enabled APTL profiles."""
    selected = [
        profile
        for profile in configured_profiles(config)
        if profile in plan_profiles
    ]
    for profile in CORE_PROFILES:
        if profile not in selected:
            selected.append(profile)
    return selected


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


def _register_service_profiles(
    alias_to_profiles: dict[str, set[str]],
    service_name: str,
    service_def: object,
) -> None:
    """Add one Compose service's aliases to the profile index."""
    if not isinstance(service_def, Mapping):
        return
    profiles = _service_profiles(service_def)
    if not profiles:
        return
    for alias in _service_aliases(service_name, service_def):
        for normalized in normalized_identifier_aliases(alias):
            alias_to_profiles.setdefault(normalized, set()).update(profiles)


def _service_profiles(service_def: Mapping[str, object]) -> set[str]:
    """Return non-empty profile strings for a Compose service."""
    return {
        str(profile)
        for profile in (service_def.get("profiles") or [])
        if str(profile).strip()
    }


def _service_aliases(
    service_name: str,
    service_def: Mapping[str, object],
) -> set[str]:
    """Return service name, container name, and hostname aliases."""
    aliases = {service_name}
    for alias_key in ("container_name", "hostname"):
        alias = service_def.get(alias_key)
        if isinstance(alias, str) and alias.strip():
            aliases.add(alias)
    return aliases


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
