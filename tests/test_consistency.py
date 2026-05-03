"""Static consistency tests for APTL configuration files.

These tests validate that docker-compose.yml, aptl.json, scripts, and code
references are internally consistent. No running Docker environment needed.
"""
import json
import re
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def compose_config():
    compose_path = PROJECT_ROOT / "docker-compose.yml"
    with open(compose_path) as f:
        return yaml.safe_load(f)


@pytest.fixture
def aptl_config():
    config_path = PROJECT_ROOT / "aptl.json"
    with open(config_path) as f:
        return json.load(f)


class TestComposeConsistency:
    """Validate docker-compose.yml internal consistency."""

    def test_all_services_have_container_name(self, compose_config):
        """Every service must have an explicit container_name."""
        services = compose_config.get("services", {})
        missing = []
        for name, svc in services.items():
            if "container_name" not in svc:
                missing.append(name)
        assert not missing, (
            f"Services missing container_name: {missing}. "
            "Auto-generated names break when repo is cloned to a different directory."
        )

    def test_container_names_are_unique(self, compose_config):
        """All container_name values must be unique."""
        services = compose_config.get("services", {})
        names = [
            svc["container_name"]
            for svc in services.values()
            if "container_name" in svc
        ]
        dupes = [n for n in names if names.count(n) > 1]
        assert not dupes, f"Duplicate container_name values: {set(dupes)}"

    def test_static_ipv4_addresses_are_unique_per_network(self, compose_config):
        """Static container IPs must not collide within the same Docker network."""
        services = compose_config.get("services", {})
        seen: dict[tuple[str, str], str] = {}
        dupes: list[tuple[str, str, str, str]] = []

        for service_name, svc in services.items():
            networks = svc.get("networks", {})
            if not isinstance(networks, dict):
                continue

            for network_name, network_cfg in networks.items():
                if not isinstance(network_cfg, dict):
                    continue

                ip = network_cfg.get("ipv4_address")
                if not ip:
                    continue

                key = (network_name, ip)
                if key in seen:
                    dupes.append((network_name, ip, seen[key], service_name))
                else:
                    seen[key] = service_name

        assert not dupes, (
            "Duplicate static ipv4_address assignments:\n"
            + "\n".join(
                f"  {network}: {ip} used by {first} and {second}"
                for network, ip, first, second in dupes
            )
        )


class TestCodeReferencesMatchCompose:
    """Ensure docker exec references in code match actual container_name values."""

    def test_docker_exec_references(self, compose_config):
        """All 'docker exec <name>' in .py and .sh files must reference a real container_name."""
        services = compose_config.get("services", {})
        valid_names = {
            svc["container_name"]
            for svc in services.values()
            if "container_name" in svc
        }

        pattern = re.compile(r"docker\s+exec\s+(aptl-[\w.-]+)")
        bad_refs = []

        for ext in ("**/*.py", "**/*.sh"):
            for fpath in PROJECT_ROOT.glob(ext):
                if "node_modules" in str(fpath):
                    continue
                text = fpath.read_text(errors="replace")
                for match in pattern.finditer(text):
                    ref = match.group(1)
                    if ref not in valid_names:
                        bad_refs.append(
                            (str(fpath.relative_to(PROJECT_ROOT)), ref)
                        )

        assert not bad_refs, (
            "docker exec references to non-existent container names:\n"
            + "\n".join(f"  {f}: {n}" for f, n in bad_refs)
        )


class TestProfileConsistency:
    """Validate profiles between aptl.json and docker-compose.yml."""

    def test_config_profiles_exist_in_compose(self, compose_config, aptl_config):
        """Every profile in aptl.json containers must be used in docker-compose.yml."""
        config_profiles = set(aptl_config.get("containers", {}).keys())

        compose_profiles = set()
        for svc in compose_config.get("services", {}).values():
            for p in svc.get("profiles", []):
                compose_profiles.add(p)

        missing = config_profiles - compose_profiles
        assert not missing, (
            f"Profiles in aptl.json but not in docker-compose.yml: {missing}"
        )


class TestNetworkEgressControls:
    """Validate SAF-002: attack networks must block internet egress."""

    ATTACK_NETWORKS = ["aptl-dmz", "aptl-internal", "aptl-redteam"]

    def test_attack_networks_are_internal(self, compose_config):
        """Networks carrying attack traffic must use internal: true."""
        networks = compose_config.get("networks", {})
        not_internal = []
        for name in self.ATTACK_NETWORKS:
            net = networks.get(name, {})
            if not net.get("internal", False):
                not_internal.append(name)
        assert not not_internal, (
            f"SAF-002 violation: attack networks missing internal: true: "
            f"{not_internal}. Containers on these networks can reach the "
            f"internet, risking autonomous agent attacks on external targets."
        )

    def test_security_network_allows_egress(self, compose_config):
        """Security/management network must NOT be internal (SOC tools need internet)."""
        networks = compose_config.get("networks", {})
        security = networks.get("aptl-security", {})
        assert not security.get("internal", False), (
            "aptl-security must not be internal: true. "
            "SOC tools (MISP, Wazuh, Shuffle) require internet for "
            "threat feeds and rule updates."
        )


class TestBuildScriptCoverage:
    """Validate build-all-mcps.sh covers all MCP server directories."""

    def test_all_mcp_servers_in_build_script(self):
        """Every mcp-* directory should be built by build-all-mcps.sh."""
        mcp_dir = PROJECT_ROOT / "mcp"
        build_script = mcp_dir / "build-all-mcps.sh"

        server_dirs = {
            d.name
            for d in mcp_dir.iterdir()
            if d.is_dir() and d.name.startswith("mcp-")
        }

        script_text = build_script.read_text()

        missing = {s for s in server_dirs if s not in script_text}
        assert not missing, f"MCP servers not in build-all-mcps.sh: {missing}"
