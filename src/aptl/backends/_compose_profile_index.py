"""Compose profile index data model and identifier normalization.

The dataclasses that hold a resolved Compose service/profile index, plus the
identifier-normalization primitives they and the loader share, live here apart
from the loading logic in :mod:`aptl.backends.raes_profiles`. That keeps this a
dependency-free leaf — it imports nothing from the loader — so the loader can
import it without a cycle. ``raes_profiles`` re-exports the public names below,
so existing ``from aptl.backends.raes_profiles import ComposeProfileIndex``
imports keep working.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

IDENTIFIER_SEPARATORS = re.compile(r"[^a-z0-9]+")


def normalize_identifier(raw: str) -> str:
    """Normalize punctuation and case for loose identifier matching."""
    lowered = raw.strip().lower()
    return IDENTIFIER_SEPARATORS.sub("-", lowered).strip("-")


def normalized_identifier_aliases(raw: str) -> set[str]:
    """Return normalized aliases for one Compose or RAES identifier."""
    normalized = normalize_identifier(raw)
    if not normalized:
        return set()
    aliases = {normalized}
    if normalized.startswith("aptl-"):
        aliases.add(normalized.removeprefix("aptl-"))
    return {alias for alias in aliases if alias}


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
        profile, not just the RAES nodes a scenario declares. When an activated
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
