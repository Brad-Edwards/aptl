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

# Published host ports are parameterized (`${VAR:-default}`) so `aptl lab start`
# can remap an in-use default to a free port. Resolve to the default so these
# static checks compare against the value the stack publishes out of the box.
_COMPOSE_VAR = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::-([^}]*))?\}")


def _resolve_compose_vars(text: str) -> str:
    return _COMPOSE_VAR.sub(lambda m: m.group(1) or "", text)


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
        ownership, issue #325). ``suricata`` (still Compose-managed) and
        ``misp-suricata-sync`` (realized generically from the SDL, issue
        #581, via ``runtime.mounts`` — never a Compose volume mount) share
        the ``suricata_misp_rules`` named volume instead. The env-var side
        of misp-suricata-sync's config (RULES_OUT_PATH, MISP_API_KEY, ...)
        is a separate, not-yet-built secrets-injection concern for
        image-free nodes (tracked alongside #809) and is not asserted here.
        """
        from aces_sdl import parse_sdl_file
        from aces_sdl.runtime_mounts import RuntimeMountSourceKind

        services = compose_config["services"]
        suricata_volumes = services["suricata"]["volumes"]

        misp_mount = "suricata_misp_rules:/var/lib/suricata/rules/misp:rw"
        assert misp_mount in suricata_volumes

        # No host bind (checked-in or .aptl) onto the chowned rules tree.
        assert not any(
            volume.startswith("./") and "/var/lib/suricata/rules/misp" in volume
            for volume in suricata_volumes
        )
        # The seed volumes are declared at top level (project-scoped, no
        # explicit global name).
        top_level = compose_config.get("volumes", {})
        assert "suricata_misp_rules" in top_level
        assert "suricata_config_seed" in top_level

        scenario = parse_sdl_file(
            PROJECT_ROOT / "scenarios" / "techvault-operational.sdl.yaml"
        )
        sync_node = scenario.nodes["misp-suricata-sync"]
        volume_mounts = {
            mount.source: mount.target
            for mount in sync_node.runtime.mounts
            if mount.source_kind == RuntimeMountSourceKind.VOLUME
        }
        assert volume_mounts.get("suricata_misp_rules") == "/var/lib/suricata/rules/misp"
        assert volume_mounts.get("suricata_command_socket") == "/var/run/suricata"

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

    def test_thehive_elasticsearch_stays_writable_on_full_host(
        self, compose_config
    ):
        """Fresh TheHive and Cortex bootstrap must not depend on host usage.

        Elasticsearch's percentage flood-stage can reject the first Cortex
        organisation write while cluster health remains green. The lab store
        is disposable and single-node, so host percentage watermarks are not
        an appropriate readiness policy.
        """
        environment = compose_config["services"]["thehive-es"]["environment"]

        assert (
            "cluster.routing.allocation.disk.threshold_enabled=false"
            in environment
        )

    def test_shuffle_opensearch_stays_writable_on_full_host(
        self, compose_config
    ):
        """Shuffle's lab datastore must not use host percentage watermarks.

        A container can share a large, mostly-full host filesystem and still
        have ample absolute free space. OpenSearch's default flood-stage
        watermark then makes indices read-only while its healthcheck remains
        green, so the first-load Shuffle workflow silently fails to seed.
        """
        environment = compose_config["services"]["shuffle-opensearch"][
            "environment"
        ]

        assert (
            "cluster.routing.allocation.disk.threshold_enabled=false"
            in environment
        )

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
    its readiness must reflect the usable surface, not just port 22.

    kali is realized generically from the SDL (issue #581), never
    Compose-started, so these two properties no longer live in
    docker-compose.yml — they are asserted against the SDL node instead.
    """

    @staticmethod
    def _kali_node():
        from aces_sdl import parse_sdl_file

        scenario = parse_sdl_file(
            PROJECT_ROOT / "scenarios" / "techvault-operational.sdl.yaml"
        )
        return scenario.nodes["kali"]

    def test_kali_runs_under_systemd_reaper(self):
        """kali must declare service_manager_units so the generic
        materializer boots it on the init-capable systemd base image
        (`base_image_for_os`, src/aptl/backends/aces_materializer.py) —
        systemd is PID 1 there and reaps orphaned children natively.
        Without any service unit declared, kali would get the bare
        non-service base image instead, with no reaper (the zombie defect
        in issue #293, now a property of image selection, not a Compose
        `init: true` flag)."""
        kali = self._kali_node()
        assert kali.runtime is not None and kali.runtime.service_manager_units, (
            "kali must declare at least one service_manager_units entry "
            "(ADR-033 §2 / issue #293): with none, the materializer selects "
            "the non-service base image, which has no PID-1 reaper."
        )

    def test_kali_capture_wiring_is_verified_not_a_bare_port_probe(self):
        """kali's readiness must reflect the usable surface — sshd AND the
        OBS-003 ForceCommand capture wrapper — not merely an open port
        (ADR-033 §2). The generic materializer's read-after-write
        verification of these two service units (fail-closed: a lab start
        does not report ready if either is not observed active) replaces
        the old aptl-healthcheck.sh script."""
        kali = self._kali_node()
        unit_names = {
            unit.unit_name for unit in kali.runtime.service_manager_units
        }
        assert "ssh.service" in unit_names, "kali must run and verify sshd"
        assert "kali-capture-bootstrap.service" in unit_names, (
            "kali must run and verify the unit that wires the OBS-003 "
            "ForceCommand capture wrapper — sshd alone is exactly the bare "
            "port-22 probe this test exists to reject"
        )

    def test_kali_loopback_ssh_proxy_matches_mcp_red(self, compose_config):
        """mcp-red must use a host-routable Kali SSH endpoint.

        Docker VM backends do not route Compose bridge IPs back to the host,
        so the SSH-based MCP server needs the loopback-only proxy published
        by docker-compose.yml.
        """
        services = compose_config["services"]
        kali = services["kali"]
        assert "aptl-control" not in kali.get("networks", {}), (
            "kali must not attach to aptl-control; only the SSH proxy should "
            "publish a host-routable control endpoint"
        )

        proxy = services["kali-ssh-proxy"]
        assert proxy["container_name"] == "aptl-kali-ssh-proxy"
        resolved_ports = [
            _resolve_compose_vars(str(p)) for p in proxy.get("ports", [])
        ]
        assert "127.0.0.1:2023:2023" in resolved_ports, (
            "kali-ssh-proxy must publish 127.0.0.1:2023 by default so host-run "
            "MCP clients work on Docker Desktop, Colima, and WSL2"
        )
        assert set(proxy.get("networks", {})) == {
            "aptl-control",
            "aptl-redteam",
        }, (
            "kali-ssh-proxy should bridge only the host-published control "
            "network and Kali's red-team network"
        )

        mcp_config = json.loads(
            (PROJECT_ROOT / "mcp/mcp-red/docker-lab-config.json").read_text(
                encoding="utf-8"
            )
        )
        kali_mcp = mcp_config["containers"]["kali"]
        assert kali_mcp["container_ip"] == "localhost"
        assert kali_mcp["ssh_port"] == 2023


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
