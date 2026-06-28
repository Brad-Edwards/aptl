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

    def test_misp_suricata_rules_mount_named_volume(self, compose_config):
        """ADR-043: MISP rules ride a shared named volume, never a host bind.

        Nothing checked-in or under ``.aptl/`` may be bind-mounted onto a
        path the Suricata image entrypoint chowns (that rewrote host-side
        ownership, issue #325). Both ``suricata`` and ``misp-suricata-sync``
        share the ``suricata_misp_rules`` named volume instead.
        """
        services = compose_config["services"]

        suricata_volumes = services["suricata"]["volumes"]
        sync_volumes = services["misp-suricata-sync"]["volumes"]

        misp_mount = "suricata_misp_rules:/var/lib/suricata/rules/misp:rw"
        assert misp_mount in suricata_volumes
        assert misp_mount in sync_volumes

        # No host bind (checked-in or .aptl) onto the chowned rules tree.
        all_volumes = suricata_volumes + sync_volumes
        assert not any(
            volume.startswith("./") and "/var/lib/suricata/rules/misp" in volume
            for volume in all_volumes
        )
        # The seed volumes are declared at top level (project-scoped, no
        # explicit global name).
        top_level = compose_config.get("volumes", {})
        assert "suricata_misp_rules" in top_level
        assert "suricata_config_seed" in top_level

        assert (
            "RULES_OUT_PATH=/var/lib/suricata/rules/misp/misp-iocs.rules"
            in services["misp-suricata-sync"]["environment"]
        )

    def test_suricata_config_seeded_not_bind_mounted(self, compose_config):
        """ADR-043: suricata.yaml / local.rules are seeded via a named volume
        and staged by the wrapper entrypoint, never bind-mounted from the
        checked-in tree onto the chowned /etc/suricata path."""
        suricata = compose_config["services"]["suricata"]
        volumes = suricata["volumes"]

        assert "suricata_config_seed:/seed:ro" in volumes
        assert not any(
            volume.startswith("./config/suricata/") for volume in volumes
        )
        # Wrapper entrypoint stages the seed into image-owned /etc/suricata
        # then delegates to the upstream entrypoint.
        entrypoint = "\n".join(suricata["entrypoint"])
        assert "/seed/suricata.yaml" in entrypoint
        assert "exec /docker-entrypoint.sh" in entrypoint

    def test_otel_collector_healthcheck_uses_image_binary(self, compose_config):
        """The OTEL collector image is distroless, so the healthcheck cannot
        depend on shell utilities such as wget or curl."""
        collector = compose_config["services"]["aptl-otel-collector"]
        test = collector.get("healthcheck", {}).get("test")

        assert test == [
            "CMD",
            "/otelcol-contrib",
            "validate",
            "--config",
            "/etc/otelcol-contrib/config.yaml",
        ]

    def test_web_api_token_does_not_block_inactive_profiles(self, compose_config):
        """Compose expands environment substitutions for inactive profiles, so
        the optional web token must be validated by the web runtime instead of
        by `${VAR:?}` interpolation in docker-compose.yml."""
        api_env = compose_config["services"]["aptl-web-api"]["environment"]
        token_lines = [
            line for line in api_env if line.startswith("APTL_API_TOKEN=")
        ]

        assert token_lines == ["APTL_API_TOKEN=${APTL_API_TOKEN:-}"]
        assert not any(":?" in line for line in token_lines)

    def test_web_ui_does_not_carry_control_plane_token(self, compose_config):
        """UI-008a: the control-plane token is custodied only by the FastAPI BFF
        (aptl-web-api). The static-SPA + reverse-proxy UI container must not
        receive APTL_API_TOKEN — it holds no secret and enforces no auth."""
        ui = compose_config["services"]["aptl-web-ui"]
        env_lines = ui.get("environment", []) or []
        assert not any(
            "APTL_API_TOKEN" in line for line in env_lines
        ), "aptl-web-ui must not carry the control-plane token (UI-008a)"


class TestKaliContainerLifecycle:
    """Issue #293 / ADR-033 §2: the kali container must reap children and
    its healthcheck must reflect the usable surface, not just port 22."""

    def test_kali_service_runs_under_init_reaper(self, compose_config):
        """The kali service must set `init: true` so Docker injects an
        init/reaper (docker-init / tini) as PID 1. Without it the
        entrypoint's `exec sleep infinity` is PID 1 and cannot reap
        orphaned children — the zombie defect in issue #293."""
        kali = compose_config["services"]["kali"]
        assert kali.get("init") is True, (
            "kali service must set `init: true` (ADR-033 §2): PID 1 must "
            "reap children, otherwise red-team-spawned background processes "
            "zombie out (issue #293)."
        )

    def test_kali_healthcheck_is_not_bare_port_probe(self, compose_config):
        """The kali healthcheck must not be the port-22-only probe — that
        masks a failed boot-time child behind an open SSH port
        (ADR-033 §2). It must invoke the readiness healthcheck script."""
        kali = compose_config["services"]["kali"]
        test = kali.get("healthcheck", {}).get("test")
        assert test, "kali service must define a healthcheck"
        joined = " ".join(test) if isinstance(test, list) else str(test)
        assert "aptl-healthcheck.sh" in joined, (
            "kali healthcheck must invoke /usr/local/bin/aptl-healthcheck.sh, "
            f"which verifies sshd + the ForceCommand wrapper + the boot "
            f"readiness marker — not just an open port; got: {test!r}"
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
