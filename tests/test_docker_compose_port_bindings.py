"""Host port-binding policy for the lab's docker-compose stack (issue #416).

SOC / control-plane management surfaces are operator tooling, not deliberately
vulnerable victim targets. Per ADR-034 (Host Exposure Amendment) they must be
published to ``127.0.0.1`` so they are not reachable from other machines on the
operator's LAN. Deliberate attack-surface services (the enterprise victim
targets) must stay published on all interfaces so the in-range red team can
reach them.

This test parses the base and backend-observability Compose assets and pins both
halves of that boundary, so a future edit cannot silently re-expose a SOC
management port nor accidentally loopback-bind a victim target.
"""

import re
from pathlib import Path

import pytest
import yaml

# Compose variable references (``${VAR}`` / ``${VAR:-default}``) can appear in a
# port mapping — published host ports are parameterized so `aptl lab start` can
# remap an in-use default to a free port. Resolve to the default (the binding
# used when the operator sets no override) so the policy below is checked
# against the value the stack publishes out of the box.
_COMPOSE_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _resolve_compose_vars(text: str) -> str:
    return _COMPOSE_VAR.sub(lambda m: m.group(2) or "", text)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = PROJECT_ROOT / "docker-compose.yml"
OBSERVABILITY_COMPOSE_PATH = PROJECT_ROOT / "docker-compose.observability.yml"

# SOC / control-plane management surfaces that MUST bind loopback only.
# Each entry is (service_name, host_port) for every host-published port.
MANAGEMENT_SURFACES = [
    ("wazuh.manager", 1514),
    ("wazuh.manager", 1515),
    ("wazuh.manager", 514),
    ("wazuh.manager", 55000),
    ("wazuh.indexer", 9200),
    ("wazuh.dashboard", 443),
    ("misp", 8443),
    ("thehive", 9000),
    ("shuffle-frontend", 3443),
    ("shuffle-frontend", 3001),
    ("cortex", 9001),
    ("aptl-otel-collector", 4317),
    ("aptl-otel-collector", 4318),
    ("aptl-tempo", 3200),
    ("aptl-grafana-otel", 3100),
    # mailserver holds fixture credentials (a known lab password), so its
    # SMTP/IMAP host publishes must NOT be reachable on 0.0.0.0 where an
    # exposed host becomes an open, known-cred relay (issue #668). The in-range
    # phishing path (kali -> victims) uses the docker networks, not these host
    # publishes, so loopback binding does not reduce attack realism.
    ("mailserver", 25),
    ("mailserver", 143),
    ("mailserver", 587),
    ("mailserver", 993),
    # The web API and UI are the operator's own control plane (ADR-039).
    ("aptl-web-api", 8400),
    ("aptl-web-ui", 3000),
    # The reverse-engineering workstation is defender tooling, not a target.
    ("reverse", 2027),
]

# Deliberate victim / attack-surface targets that MUST remain reachable on all
# interfaces (NOT loopback-bound). Encodes the other half of the policy.
TARGET_SURFACES = [
    # webapp's host publication is gone with its proxy (issue #1006): TechVault
    # declares no such node, nothing started it, and the attack path reaches the
    # portal inside the range. dns is the remaining declared public surface.
    ("dns", 5353),
]


def _parse_port(entry) -> tuple[str | None, int | None, str]:
    """Parse a compose short-syntax port mapping into (host_ip, host_port, proto).

    Accepts ``"ip:host:container"``, ``"host:container"``, ``"container"`` and a
    ``/proto`` suffix on the container port. Long-form dict entries are returned
    with their ``host_ip`` (defaulting to all-interfaces when unset).
    """
    if isinstance(entry, dict):
        host_ip = entry.get("host_ip")
        published = entry.get("published")
        host_port = int(published) if published is not None else None
        return host_ip, host_port, str(entry.get("protocol", "tcp"))

    text = str(entry)
    proto = "tcp"
    if "/" in text:
        text, proto = text.rsplit("/", 1)
    text = _resolve_compose_vars(text)
    parts = text.split(":")
    if len(parts) == 3:
        host_ip, host_port, _container = parts
        return host_ip, int(host_port), proto
    if len(parts) == 2:
        host_port, _container = parts
        return None, int(host_port), proto  # no host_ip => all interfaces
    return None, None, proto


@pytest.fixture(scope="module")
def compose() -> dict:
    base = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    observability = yaml.safe_load(
        OBSERVABILITY_COMPOSE_PATH.read_text(encoding="utf-8")
    )
    base["services"].update(observability.get("services", {}))
    return base


def _published_for(compose: dict, service: str, host_port: int):
    svc = compose["services"][service]
    matches = []
    for entry in svc.get("ports", []):
        host_ip, parsed_port, _proto = _parse_port(entry)
        if parsed_port == host_port:
            matches.append((host_ip, entry))
    return matches


@pytest.mark.parametrize("service,host_port", MANAGEMENT_SURFACES)
def test_management_surface_is_loopback_bound(compose, service, host_port):
    matches = _published_for(compose, service, host_port)
    assert matches, f"{service} no longer publishes host port {host_port}"
    for host_ip, entry in matches:
        assert host_ip == "127.0.0.1", (
            f"{service} host port {host_port} must bind 127.0.0.1 (ADR-034 "
            f"Host Exposure Amendment), got {entry!r}"
        )


@pytest.mark.parametrize("service,host_port", TARGET_SURFACES)
def test_victim_target_stays_publicly_reachable(compose, service, host_port):
    matches = _published_for(compose, service, host_port)
    assert matches, f"{service} no longer publishes host port {host_port}"
    for host_ip, entry in matches:
        assert host_ip in (None, "0.0.0.0", "::"), (
            f"{service} host port {host_port} is a deliberate attack-surface "
            f"target and must stay reachable on all interfaces (no host-IP "
            f"prefix, or an explicit all-interfaces bind); a specific host IP "
            f"would break red-team reachability, got {entry!r}"
        )


def test_every_published_port_is_classified(compose):
    """A host publication nobody classified is one nobody checked.

    The management and target lists were hand-maintained, so the web API, web
    UI and reverse workstation publications were never checked — and reverse
    was published on all interfaces (issue #1006). Every host-published port
    must now appear in exactly one list.
    """
    classified = set(MANAGEMENT_SURFACES) | set(TARGET_SURFACES)
    unclassified = sorted(
        (service, host_port)
        for service, definition in compose["services"].items()
        for entry in definition.get("ports", []) or []
        for _host_ip, host_port, _proto in [_parse_port(entry)]
        if host_port is not None and (service, host_port) not in classified
    )
    assert not unclassified, (
        f"host-published ports with no exposure classification: {unclassified}; "
        "add each to MANAGEMENT_SURFACES or TARGET_SURFACES"
    )
    assert not set(MANAGEMENT_SURFACES) & set(TARGET_SURFACES)
