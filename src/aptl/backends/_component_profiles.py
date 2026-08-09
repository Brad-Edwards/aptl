"""APTL operator packaging: which components map to which start profile.

This is the interim home (issue #895) for pack<->backend deployment-serving
configuration: which of APTL's own components belong to which operator
start-profile (the ``aptl.json`` ``containers`` toggles: ``wazuh`` / ``soc`` /
``enterprise`` / ``victim`` / ``kali`` / ``fileshare`` / ``dns`` / ``mail`` /
``reverse`` / ``web``).

This is **operator packaging, not realization.** It only labels components the
core already realizes from the SDL so an operator can boot a subset; it never
decides *what* a node realizes to or *how*. When a scenario ships as an env-pack
there is no ``docker-compose.yml`` to carry the ``profiles:`` column and the SDL
cannot express it (the RAES ``Node`` model forbids vendor keys and ``roles`` is
local identity), so the grouping lives here. The mapping mirrors the profiles
column of the retiring in-tree ``docker-compose.yml`` exactly; issue #895 tracks
moving it onto a first-class pack<->backend seam so it does not calcify in core.
"""

from __future__ import annotations

from aptl.backends._compose_profile_index import normalized_identifier_aliases

# Component identity -> operator start-profile. Keyed by the node's terminal
# name (the ``provision.node.<name>`` tail), normalized. Behaviour-preserving
# with the retiring docker-compose.yml ``profiles:`` column.
_COMPONENT_PROFILE: dict[str, str] = {
    # wazuh SIEM stack
    "wazuh-manager": "wazuh",
    "wazuh-indexer": "wazuh",
    "wazuh-dashboard": "wazuh",
    # SOC tooling
    "suricata": "soc",
    "misp": "soc",
    "misp-db": "soc",
    "misp-redis": "soc",
    "misp-suricata-sync": "soc",
    "thehive": "soc",
    "thehive-cassandra": "soc",
    "thehive-es": "soc",
    "cortex": "soc",
    # Retained for the legacy in-tree docker-compose.yml (a still-live, separately
    # tested static stack distinct from the ADR-088 env-pack conversion, #889):
    # its ``cortex-index-init`` one-shot service and scripts/cortex-index-init.sh
    # are still real and still exercised by scripts/cortex-apikey.sh. Only the
    # env-pack-declared TechVault pack retired the one-shot; this entry must stay
    # for test_component_profiles.py's compose/grouping parity check.
    "cortex-index-init": "soc",
    "shuffle-backend": "soc",
    "shuffle-frontend": "soc",
    "shuffle-opensearch": "soc",
    "shuffle-orborus": "soc",
    "wazuh-sidecar-db": "soc",
    "wazuh-sidecar-suricata": "soc",
    # enterprise victim environment
    "ad": "enterprise",
    "db": "enterprise",
    "webapp": "enterprise",
    "webapp-proxy": "enterprise",
    "workstation": "enterprise",
    # single-profile subsystems
    "dns": "dns",
    "fileshare": "fileshare",
    "victim": "victim",
    "kali": "kali",
    "kali-capture": "kali",
    "kali-ssh-proxy": "kali",
    "mailserver": "mail",
    "reverse": "reverse",
    # observability core (always started via CORE_PROFILES=("otel",)). These
    # nodes carry an ``aptl-`` prefix in their own name; lookups strip it, so
    # key them without it here.
    "otel-collector": "otel",
    "tempo": "otel",
    "grafana-otel": "otel",
    # optional web console
    "web-api": "web",
    "web-ui": "web",
}


def component_profile(name: str) -> str | None:
    """Return the operator start-profile for one component name, or ``None``.

    ``name`` is the node's terminal identity (the ``provision.node.<name>``
    tail). Matching is prefix-robust: a component whose own name carries an
    ``aptl-`` prefix and one that does not both resolve. ``None`` means the
    component is not grouped into any operator profile, so profile selection
    must fall back to other signals.
    """

    for alias in normalized_identifier_aliases(name):
        profile = _COMPONENT_PROFILE.get(alias)
        if profile is not None:
            return profile
    return None


def component_profiles(name: str) -> frozenset[str]:
    """Return the operator start-profiles for one component name (0 or 1)."""

    profile = component_profile(name)
    return frozenset({profile}) if profile is not None else frozenset()
