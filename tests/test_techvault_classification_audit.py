"""Regression checks for the TechVault SDL classification audit fixes."""

from pathlib import Path
import json

import pytest
import yaml

from tests.techvault_sdl import load_legacy_techvault_sdl


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
COMPOSE_PATH = PROJECT_ROOT / "docker-compose.yml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"
SHUFFLE_EVIDENCE = PROJECT_ROOT / "docs" / "aces" / "inventory" / "shuffle-backend" / "evidence"


def _yaml(path: Path):
    if path == TECHVAULT_SDL_PATH:
        return load_legacy_techvault_sdl(str(path))
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _json(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _rows() -> dict[str, dict]:
    return {row["id"]: row for row in _yaml(PARITY_PATH)["rows"]}


def test_shuffle_backend_runtime_inventory_is_encoded_from_evidence():
    sdl = _yaml(TECHVAULT_SDL_PATH)
    node = sdl["nodes"]["shuffle-backend"]
    runtime = node["runtime"]
    container = _json(SHUFFLE_EVIDENCE / "docker-inspect.container.json")[0]
    findings = _json(SHUFFLE_EVIDENCE / "trivy-vulnerability-list.json")

    assert node["source"]["version"] == (
        "ghcr.io/shuffle/shuffle-backend@"
        "sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d"
    )
    assert node["os_version"] == "Alpine Linux 3.22.2"
    services = {(service["port"], service["protocol"], service["name"]) for service in node["services"]}
    assert services == {(5001, "tcp", "shuffle-api")}

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert mounts["/shuffle-database"]["source_kind"] == "volume"
    assert mounts["/shuffle-database"]["source"] == "aptl_shuffle_data"
    assert mounts["/var/run/docker.sock"]["source_kind"] == "bind"
    assert mounts["/var/run/docker.sock"]["read_only"] is False

    controls = {item["path"]: item for item in runtime["local_control_interfaces"]}
    assert controls["/var/run/docker.sock"]["access"] == "read_write"
    assert "process" not in runtime, (
        "ACES PR #458 removed runtime.process; PID 1 shufflebackend identity is "
        "carried as processes[0]."
    )
    assert runtime["processes"][0]["command"] == ["./shufflebackend"]
    assert runtime["processes"][0]["user"] == "root"
    assert runtime["processes"][0]["pid"] == 1
    assert len(runtime["packages"]) == 21
    assert len(runtime["package_vulnerabilities"]) == len(findings) == 90
    assert {finding["severity"] for finding in runtime["package_vulnerabilities"]} == {
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
    }

    endpoint = runtime["network"]["endpoints"][0]
    observed = container["NetworkSettings"]["Networks"]["aptl_aptl-security"]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == observed["IPAddress"] == "172.20.0.20"
    assert endpoint["aliases"] == observed["Aliases"]

    secret_env = {
        item["name"]: item
        for item in runtime["environment"]
        if item["value_classification"] == "redacted"
    }
    assert set(secret_env) == {
        "SHUFFLE_DEFAULT_APIKEY",
        "SHUFFLE_DEFAULT_PASSWORD",
        "SHUFFLE_OPENSEARCH_PASSWORD",
    }
    assert all(item["value"] == "" for item in secret_env.values())


def test_wazuh_manager_sdl_matches_compose_visible_surfaces():
    sdl = _yaml(TECHVAULT_SDL_PATH)
    compose = _yaml(COMPOSE_PATH)
    node = sdl["nodes"]["wazuh-manager"]
    runtime = node["runtime"]
    service = compose["services"]["wazuh.manager"]

    service_bindings = {(item["port"], item["protocol"]) for item in node["services"]}
    assert service_bindings == {(1514, "tcp"), (1515, "tcp"), (514, "udp"), (55000, "tcp")}
    assert node["conditions"] == {"wazuh-api-ready": "wazuh-root"}
    assert sdl["conditions"]["wazuh-api-ready"]["command"] == (
        "curl -ks https://localhost:55000 || exit 1"
    )
    assert runtime["health"]["status"] == "healthy"

    infra = sdl["infrastructure"]["wazuh-manager"]
    assert infra["links"] == ["security-net", "dmz-net", "internal-net"]
    assert infra["properties"] == [
        {"security-net": "172.20.0.10"},
        {"dmz-net": "172.20.1.10"},
        {"internal-net": "172.20.2.30"},
    ]

    endpoints = {endpoint["network"]: endpoint for endpoint in runtime["network"]["endpoints"]}
    assert endpoints["security-net"]["ip_address"] == service["networks"]["aptl-security"]["ipv4_address"]
    assert endpoints["dmz-net"]["ip_address"] == service["networks"]["aptl-dmz"]["ipv4_address"]
    assert endpoints["internal-net"]["ip_address"] == service["networks"]["aptl-internal"]["ipv4_address"]
    assert {port["container_port"] for port in runtime["network"]["published_ports"]} == {
        1514,
        1515,
        514,
        55000,
    }

    mount_targets = {mount["target"] for mount in runtime["mounts"]}
    assert {
        "/var/ossec/etc/decoders/samba_decoders.xml",
        "/var/ossec/etc/decoders/postgresql_decoders.xml",
        "/var/ossec/etc/rules/ad_rules.xml",
        "/var/ossec/etc/rules/webapp_rules.xml",
        "/var/ossec/etc/rules/suricata_rules.xml",
        "/var/ossec/etc/rules/database_rules.xml",
        "/wazuh-config-mount/etc/ossec.conf",
    } <= mount_targets

    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert filesystem["/var/ossec/etc/rules/webapp_rules.xml"]["source_path"] == (
        "config/wazuh_cluster/webapp_rules.xml"
    )
    assert filesystem["/wazuh-config-mount/etc/ossec.conf"]["sensitivity"] == "operator_secret"

    env = {item["name"]: item for item in runtime["environment"]}
    for name in ("INDEXER_PASSWORD", "API_PASSWORD"):
        assert env[name]["value_classification"] == "redacted"
        assert env[name]["value"] == ""


def test_switch_network_internal_flags_match_compose():
    sdl = _yaml(TECHVAULT_SDL_PATH)
    compose = _yaml(COMPOSE_PATH)
    network_map = {
        "aptl-security": "security-net",
        "aptl-dmz": "dmz-net",
        "aptl-internal": "internal-net",
        "aptl-redteam": "redteam-net",
    }

    for compose_name, sdl_name in network_map.items():
        compose_internal = bool(compose["networks"][compose_name].get("internal", False))
        sdl_internal = bool(
            sdl["infrastructure"][sdl_name]["properties"].get("internal", False)
        )
        assert sdl_internal == compose_internal, (compose_name, sdl_name)


def test_techvault_sdl_compiles_with_audit_fix_nodes():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)

    shuffle = model.node_deployments["provision.node.techvault.shuffle-backend"].spec["node"]
    wazuh = model.node_deployments["provision.node.techvault.wazuh-manager"].spec["node"]
    assert len(shuffle["runtime"]["package_vulnerabilities"]) == 90
    assert [endpoint["network"] for endpoint in wazuh["runtime"]["network"]["endpoints"]] == [
        "techvault.security-net",
        "techvault.dmz-net",
        "techvault.internal-net",
    ]


def test_parity_inventory_rows_no_longer_route_node_state_to_backend_only():
    rows = _rows()

    assert rows["scen.techvault.shuffle-backend-inventory"]["category"] == "aces_sdl"
    assert rows["scen.techvault.shuffle-backend-inventory"]["blocking_followup"] == "n/a"
    assert rows["compose.service.shuffle-backend"]["category"] == "aces_sdl"
    assert rows["compose.service.shuffle-backend"]["blocking_followup"] == "n/a"

    assert rows["scen.techvault.wazuh-manager-inventory"]["category"] == "aces_sdl"
    assert rows["compose.service.wazuh-manager"]["category"] == "aces_sdl"
    assert rows["compose.service.wazuh-manager"]["blocking_followup"] == "n/a"

    assert rows["compose.service.webapp"]["blocking_followup"] == "n/a"
    for row_id in (
        "compose.network.aptl-security",
        "compose.network.aptl-dmz",
        "compose.network.aptl-internal",
        "compose.network.aptl-redteam",
    ):
        assert rows[row_id]["category"] == "aces_sdl"
        assert rows[row_id]["blocking_followup"] == "n/a"

    assert rows["compose.profile.soc"]["category"] == "aptl_backend_responsibility"
    assert "delivery toggle" in rows["compose.profile.soc"]["notes"]
    assert rows["compose.profile.enterprise"]["category"] == "aptl_backend_responsibility"
    assert "delivery toggle" in rows["compose.profile.enterprise"]["notes"]
    assert rows["compose.volumes.summary"]["category"] == "validation_gate"
