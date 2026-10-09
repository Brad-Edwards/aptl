"""Host port-binding policy for the lab's docker-compose stack (issue #416).

SOC / control-plane management surfaces are operator tooling, not deliberately
vulnerable victim targets. Per ADR-034 (Host Exposure Amendment) they must be
published to ``127.0.0.1`` so they are not reachable from other machines on the
operator's LAN. No victim target is host-published: the in-range red team
reaches the victims over the Docker networks. The webapp proxy's publication
went with issue #1006, and the dns stub's all-interface publication with issue
#1004.

This test pins that boundary on two models, so a future edit cannot silently
re-expose a SOC management port or add a host publication nobody classified:

- the base and backend-observability Compose assets, which an explicit
  project-tree scenario starts as written; and
- the publications the planner renders for the pinned TechVault pack, which
  ``aptl lab start`` runs by default without reading the root
  ``docker-compose.yml`` (#954).
"""

import re
from pathlib import Path

import pytest
import yaml

from aptl.core.deployment._compose_port_realization import compose_port_entry

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

# The same boundary on the pinned TechVault pack's rendered publications. Its
# nodes keep the pack's names, so the Wazuh services are hyphenated here.
RENDERED_MANAGEMENT_SURFACES = [
    ("wazuh-manager", 1514),
    ("wazuh-manager", 1515),
    ("wazuh-manager", 514),
    ("wazuh-manager", 55000),
    ("wazuh-indexer", 9200),
    ("wazuh-dashboard", 443),
    ("misp", 8443),
    ("thehive", 9000),
    ("shuffle-frontend", 3443),
    ("shuffle-frontend", 3001),
    ("cortex", 9001),
]

# Each checked model's fixture name, with the surfaces classified on it.
SURFACES_BY_MODEL = {
    "compose": MANAGEMENT_SURFACES,
    "rendered": RENDERED_MANAGEMENT_SURFACES,
}


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


@pytest.fixture(scope="module")
def rendered(rendered_techvault_spec) -> dict:
    """Every node publication the realization carries for the pinned TechVault pack.

    `aptl lab start` writes an image node's publications into the Compose port
    override and a base-container node's into its own ``docker run -p``. Both
    render these declarations, so each node is checked here whichever way it
    starts. Backend apparatus outside the realization, such as the
    operator-access relays, is checked in ``tests/test_operator_access.py``.
    """
    return {
        "services": {
            node.name: {"ports": [compose_port_entry(p) for p in node.published_ports]}
            for node in rendered_techvault_spec.nodes
            if node.published_ports
        }
    }


def _published_for(compose: dict, service: str, host_port: int):
    svc = compose["services"].get(service, {})
    matches = []
    for entry in svc.get("ports", []):
        host_ip, parsed_port, _proto = _parse_port(entry)
        if parsed_port == host_port:
            matches.append((host_ip, entry))
    return matches


@pytest.mark.parametrize(
    "model,service,host_port",
    [
        (model, service, host_port)
        for model, surfaces in SURFACES_BY_MODEL.items()
        for service, host_port in surfaces
    ],
)
def test_management_surface_is_loopback_bound(request, model, service, host_port):
    matches = _published_for(request.getfixturevalue(model), service, host_port)
    assert matches, f"{service} no longer publishes host port {host_port}"
    for host_ip, entry in matches:
        assert host_ip == "127.0.0.1", (
            f"{service} host port {host_port} must bind 127.0.0.1 (ADR-034 "
            f"Host Exposure Amendment), got {entry!r}"
        )


@pytest.mark.parametrize("model", sorted(SURFACES_BY_MODEL))
def test_every_published_port_is_classified(request, model):
    """A host publication nobody classified is one nobody checked.

    The management list was hand-maintained, so the web API, web UI and reverse
    workstation publications were never checked — and reverse was published on
    all interfaces (issue #1006). Every host-published port must now appear in
    its model's management surfaces, which pin it to loopback.
    """
    classified = set(SURFACES_BY_MODEL[model])
    # A publication with no fixed host port gets an ephemeral one on its
    # host_ip, so it is reported too rather than skipped.
    unclassified = sorted(
        (
            (service, host_port)
            for service, definition in request.getfixturevalue(model)[
                "services"
            ].items()
            for entry in definition.get("ports", []) or []
            for _host_ip, host_port, _proto in [_parse_port(entry)]
            if (service, host_port) not in classified
        ),
        key=str,
    )
    assert not unclassified, (
        f"host-published ports with no exposure classification: {unclassified}; "
        f"add each to SURFACES_BY_MODEL[{model!r}]"
    )
