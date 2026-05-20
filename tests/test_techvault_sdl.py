"""ACES-native TechVault SDL acceptance tests (SCN-010 / issue #319).

These tests drive ``scenarios/techvault.sdl.yaml`` through the ACES reference
parser and runtime compiler in the sibling ``../aces-sdl`` repository. They
encode the issue's acceptance criteria as structural assertions, not by
copying parity-inventory rows as a second truth source (per
``docs/aces/techvault-sdl-authoring-preflight.md``).

The ACES packages are imported under ``pytest.importorskip``: locally a dev
that has not run ``pip install -e ../aces-sdl/implementations/python``
sees the module skip; CI runs the suite with the sibling checked out.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

aces_sdl = pytest.importorskip("aces_sdl")
aces_processor_compiler = pytest.importorskip("aces_processor.compiler")

from aces_sdl import parse_sdl_file  # noqa: E402 (imports gated above)
from aces_processor.compiler import compile_runtime_model  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"

# The four legacy enterprise subnets (per scenarios/*.yaml and the
# parity inventory rows under ``compose.network.*``). The new SDL must
# expose at least these CIDRs through its infrastructure block.
EXPECTED_LEGACY_CIDRS = {
    "172.20.0.0/24",  # lab / management
    "172.20.1.0/24",  # DMZ
    "172.20.2.0/24",  # internal enterprise
    "172.20.4.0/24",  # red team / Kali
}

# Target nodes called out in the issue Scope. Each must exist by exactly
# this name (kebab-case node id) in the parsed scenario, with at least
# one declared service — that is the "enough declared structure for APTL
# backend interpretation" acceptance criterion.
REQUIRED_TARGET_NODES = (
    "webapp",
    "postgres-db",
    "samba-ad-dc",
    "fileshare",
    "mail",
    "dns",
    "windows-workstation",
)

# Vulnerability ids the issue's Scope enumerates as "vulnerabilities,
# features, conditions" surfaces. One per major attack-class so a
# missing surface fails loudly.
REQUIRED_VULNERABILITY_IDS = (
    "webapp-sql-injection",
    "samba-kerberoastable-spn",
    "smb-guest-anonymous",
)


@pytest.fixture(scope="module")
def scenario():
    assert SDL_PATH.exists(), (
        f"TechVault SDL missing at {SDL_PATH.relative_to(PROJECT_ROOT)}; "
        "SCN-010B requires authoring this file (issue #319)."
    )
    return parse_sdl_file(SDL_PATH)


@pytest.fixture(scope="module")
def runtime_model(scenario):
    return compile_runtime_model(scenario)


@pytest.fixture(scope="module")
def raw_sdl_yaml():
    return yaml.safe_load(SDL_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Acceptance: ACES reference parser accepts the document.
# ---------------------------------------------------------------------------


def test_parses_under_aces_reference_parser(scenario):
    assert scenario.name == "techvault"
    assert scenario.semantic_validated is True
    # Advisories (non-fatal warnings) are tolerated but recorded here so
    # an unexpected new one shows up in test output rather than being
    # silently absorbed.
    assert isinstance(scenario.advisories, list)


# ---------------------------------------------------------------------------
# Acceptance: compiles into ACES RuntimeModel without legacy APTL SDL.
# ---------------------------------------------------------------------------


def test_compiles_to_runtime_model(runtime_model):
    assert runtime_model.scenario_name == "techvault"
    assert runtime_model.networks, "RuntimeModel must declare at least one network."
    assert runtime_model.node_deployments, (
        "RuntimeModel must declare at least one node deployment."
    )
    assert runtime_model.feature_templates, (
        "RuntimeModel must declare at least one feature template."
    )
    assert runtime_model.agent_specs, (
        "RuntimeModel must declare at least one agent (Kali apparatus)."
    )
    assert runtime_model.objectives, (
        "RuntimeModel must declare at least one objective so APTL backend "
        "interpretation has actionable scenario state."
    )


# ---------------------------------------------------------------------------
# Acceptance: required TechVault target nodes are declared with services.
# ---------------------------------------------------------------------------


def test_required_techvault_target_nodes_declared(scenario):
    missing = [name for name in REQUIRED_TARGET_NODES if name not in scenario.nodes]
    assert not missing, (
        f"TechVault SDL is missing target nodes named in issue #319: {missing}."
    )
    nodes_without_services = [
        name
        for name in REQUIRED_TARGET_NODES
        if not getattr(scenario.nodes[name], "services", None)
    ]
    assert not nodes_without_services, (
        f"TechVault target nodes must each declare at least one service so "
        f"backend interpretation has explicit structure; offenders: "
        f"{nodes_without_services}."
    )


# ---------------------------------------------------------------------------
# Acceptance: Kali declared as first-class attacker apparatus.
# ---------------------------------------------------------------------------


def test_kali_apparatus_declared(scenario):
    assert "kali" in scenario.nodes, "Kali must be declared as a first-class node."
    kali_node = scenario.nodes["kali"]
    assert kali_node.services, "Kali must declare its own services (SSH/MCP/loot)."

    kali_infra = scenario.infrastructure.get("kali")
    assert kali_infra is not None, "Kali must appear in the infrastructure block."
    links = list(getattr(kali_infra, "links", []) or [])
    assert "aptl-dmz" in links, "Kali must attach to the DMZ network."
    assert "aptl-redteam" in links, "Kali must attach to the red-team network."

    red_agents = [
        agent_id
        for agent_id, agent in scenario.agents.items()
        if str(getattr(agent, "entity", "")).startswith("red")
    ]
    assert red_agents, (
        "Kali apparatus must be exposed as at least one ACES agent under a "
        "Red-entity (no scenario-name-only attacker)."
    )


# ---------------------------------------------------------------------------
# Acceptance: network topology preserves the four legacy subnets.
# ---------------------------------------------------------------------------


def test_network_topology_carries_four_legacy_subnets(scenario):
    declared_cidrs = set()
    for infra in scenario.infrastructure.values():
        props = getattr(infra, "properties", None) or {}
        cidr = props.get("cidr") if isinstance(props, dict) else getattr(props, "cidr", None)
        if cidr:
            declared_cidrs.add(cidr)
    missing = EXPECTED_LEGACY_CIDRS - declared_cidrs
    assert not missing, (
        f"TechVault SDL must preserve the legacy 172.20.x.0/24 subnet "
        f"layout from scenarios/prime-enterprise.yaml; missing CIDRs: "
        f"{sorted(missing)}."
    )


# ---------------------------------------------------------------------------
# Acceptance: accounts + weak-password fixtures + overprivileged service acct.
# ---------------------------------------------------------------------------


def test_accounts_and_weak_password_fixtures(scenario):
    accounts = scenario.accounts
    assert "jessica.williams" in accounts, (
        "jessica.williams is the canonical weak-AD-credential fixture."
    )
    assert "svc-backup" in accounts, (
        "svc-backup is the canonical overprivileged service account."
    )
    weak = [
        name
        for name, account in accounts.items()
        if getattr(getattr(account, "password_strength", None), "value", "") == "weak"
    ]
    assert weak, "At least one account must carry password_strength: weak."


# ---------------------------------------------------------------------------
# Acceptance: vulnerabilities cover the issue's enumerated attack surfaces.
# ---------------------------------------------------------------------------


def test_vulnerabilities_cover_issue_surfaces(scenario):
    declared = set(scenario.vulnerabilities)
    missing = [vuln for vuln in REQUIRED_VULNERABILITY_IDS if vuln not in declared]
    assert not missing, (
        f"TechVault SDL must declare at least one vulnerability per major "
        f"legacy attack class; missing: {missing}."
    )


# ---------------------------------------------------------------------------
# Acceptance: content placement (PII + backup-config creds).
# ---------------------------------------------------------------------------


def test_content_and_pii_fixtures_present(scenario):
    content = scenario.content
    assert "customers-pii" in content, (
        "customers-pii dataset (legacy PostgreSQL customer table) must be declared."
    )
    assert "backup-config-aws-creds" in content, (
        "backup_config table with deliberately weak AWS creds must be declared."
    )


# ---------------------------------------------------------------------------
# Acceptance: ACES-native scenario flow, no legacy attack_chain/steps fields.
# ---------------------------------------------------------------------------


def test_scenario_flow_is_aces_native(scenario, raw_sdl_yaml):
    assert scenario.injects, "Scenario must declare adversary injects."
    assert scenario.events, "Scenario must declare events that bind injects."
    assert scenario.scripts, "Scenario must declare scripts (time-ordered phases)."
    assert scenario.stories, "Scenario must declare at least one story."
    assert scenario.workflows, "Scenario must declare at least one workflow."

    # No legacy `attack_chain` / `steps` / `mode` / `containers` / `mitre_attack`
    # keys at the top level — those are cutover-only-archive surfaces per
    # the parity inventory.
    forbidden = {"attack_chain", "steps", "mode", "containers", "mitre_attack"}
    leaked = forbidden & set(raw_sdl_yaml.keys())
    assert not leaked, (
        f"Legacy aptl.core.sdl keys must not appear in the ACES TechVault "
        f"SDL: {sorted(leaked)}."
    )


# ---------------------------------------------------------------------------
# Defence: only ACES SDL top-level keys are present (no x-aptl-* escape).
# ---------------------------------------------------------------------------


def test_no_extension_keys_present(raw_sdl_yaml):
    from aces_sdl.scenario import Scenario  # local import: only after importorskip

    allowed = set(Scenario.model_fields.keys())
    extra = [key for key in raw_sdl_yaml.keys() if key not in allowed]
    assert not extra, (
        f"TechVault SDL must contain only ACES-native top-level keys; "
        f"unexpected: {sorted(extra)}."
    )


# ---------------------------------------------------------------------------
# Acceptance: RuntimeModel carries enough realization surface for APTL.
# ---------------------------------------------------------------------------


def test_runtime_model_has_realization_surface(runtime_model):
    # Host class — node deployments mapped onto compiled nodes.
    deployment_node_names = {
        deployment.name for deployment in runtime_model.node_deployments.values()
    }
    assert REQUIRED_TARGET_NODES[0] in deployment_node_names, (
        f"RuntimeModel.node_deployments must include the first required "
        f"target node ('{REQUIRED_TARGET_NODES[0]}') so backend "
        f"interpretation has a host-class anchor."
    )

    # Network class — at least the DMZ and internal switches.
    network_names = {network.name for network in runtime_model.networks.values()}
    assert "aptl-dmz" in network_names and "aptl-internal" in network_names, (
        "RuntimeModel.networks must include aptl-dmz and aptl-internal so "
        "backend interpretation has a network-class anchor."
    )

    # Objective bindings — proves the model carries scenario semantics, not
    # just a header.
    objective_names = {objective.name for objective in runtime_model.objectives.values()}
    assert objective_names, (
        "RuntimeModel.objectives must declare at least one objective."
    )
