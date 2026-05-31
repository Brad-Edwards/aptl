"""Checks for the SCN-010 DNS steady-state inventory bundle."""

from collections import Counter
from pathlib import Path
import gzip
import hashlib
import json
import re

import yaml

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DNS_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "dns"
DNS_DOC_PATH = DNS_DIR / "README.md"
CAPTURE_SCRIPT_PATH = DNS_DIR / "capture-evidence.sh"
LEDGER_PATH = DNS_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = DNS_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:98deb7dcc1ef3e3435bfeb4a9bffaac8a177636da8505164fba9eeee7508ec75"
IMAGE_DIGEST = f"aptl-dns@{IMAGE_ID}"
BIND_VERSION = "BIND 9.18.39-0ubuntu0.22.04.3-Ubuntu"
PACKAGE_COUNT = 187
TRIVY_FINDING_COUNT = 80
FILESYSTEM_ENTRY_COUNT = 17
LOCAL_IDENTITY_USER_COUNT = 22
LOCAL_IDENTITY_GROUP_COUNT = 43
LEDGER_FACT_COUNT = 23
FORWARD_RRSET_COUNT = 34
REVERSE_RRSET_COUNT = 16

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.dns.json",
    "docker-compose-version.json",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-dmz.json",
    "docker-network.aptl-internal.json",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.dns-logs.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "language-manifests.txt",
    "os-packages.txt",
    "osquery-apt-sources.json",
    "osquery-docker-containers.json",
    "osquery-docker-images.json",
    "osquery-installed-applications.json",
    "osquery-listening-ports.json",
    "osquery-processes.json",
    "osquery-programs.json",
    "osquery-version.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json",
    "syft-version.json",
    "trivy-sbom.cyclonedx.json",
    "trivy-version.txt",
    "trivy-vulnerabilities.json.gz",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _yaml_file(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def test_dns_inventory_note_declares_scope_and_realization_caveats():
    text = DNS_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #336",
        "aptl-dns",
        "BIND 9.18.39-0ubuntu0.22.04.3-Ubuntu",
        "AXFR",
        "non-destructive",
        "did not run",
        "aptl lab stop -v && aptl lab start",
        "ACES issue #426",
        "PR #427",
        "No known ACES expressivity gap remains",
        "mapping-ledger.yaml",
        "uv run aptl aces-inventory validate",
        "not as clean-lab rebuild proof",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"DNS inventory note missing scope markers: {missing}"


def test_dns_capture_script_pins_reproducible_toolchain_and_dns_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "normalize-syft-cyclonedx.jq",
        "named-checkconf -p /etc/bind/named.conf",
        "dig @localhost techvault.local AXFR",
        "dig @localhost 20.172.in-addr.arpa AXFR",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_dns_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(DNS_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 336
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["dns.zone.forward"] == "encoded"
    assert dispositions["dns.zone.reverse"] == "encoded"
    assert dispositions["dns.zone.dynamic-update-transfer"] == "encoded_with_caveat"
    assert dispositions["dns.capture.toolchain-baseline"] == "encoded_with_caveat"


def test_dns_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(DNS_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_dns_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_dns_evidence_sha256_manifest_matches_files():
    manifest = EVIDENCE_DIR / "evidence-sha256sums.txt"
    offenders = {}
    manifest_entries = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative_path = line.split("  ", maxsplit=1)
        manifest_entries.add(relative_path)
        path = PROJECT_ROOT / relative_path
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            offenders[relative_path] = {"expected": expected, "actual": actual}
    assert not offenders, f"Evidence checksum mismatches: {offenders}"
    evidence_files = {
        str(path.relative_to(PROJECT_ROOT))
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and path.name != "evidence-sha256sums.txt"
    }
    assert evidence_files <= manifest_entries


def test_dns_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(
        ref["path"]
        for ref in ledger["provenance"]["attestation"].get("evidence", [])
    )
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {
        f"evidence/{path.name}"
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
    }
    assert evidence_files <= refs


def test_dns_evidence_does_not_commit_raw_secret_material():
    forbidden = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|APTL\{|^Token:",
        re.MULTILINE,
    )
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
        and forbidden.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert not offenders, f"Generated secret material leaked into evidence: {offenders}"


def test_dns_container_runtime_state():
    container = _json_file("docker-inspect.container.json")[0]
    assert container["Name"] == "/aptl-dns"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "ns1.techvault.local"
    assert container["HostConfig"]["Memory"] == 536870912
    assert container["HostConfig"]["CapAdd"] == ["CAP_NET_ADMIN"]
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert "aptl_dns_logs:/var/log/named:rw" in container["HostConfig"]["Binds"]

    networks = container["NetworkSettings"]["Networks"]
    assert networks["aptl_aptl-dmz"]["IPAddress"] == "172.20.1.22"
    assert networks["aptl_aptl-internal"]["IPAddress"] == "172.20.2.27"
    assert networks["aptl_aptl-security"]["IPAddress"] == "172.20.0.25"


def test_dns_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        'VERSION="22.04.5 LTS (Jammy Jellyfish)"',
        "uid=0(root)",
        "172.20.1.22:53",
        "172.20.2.27:53",
        "172.20.0.25:53",
        "127.0.0.1:953",
        "/usr/bin/supervisord",
        "/usr/sbin/named -g -c /etc/bind/named.conf -u bind",
        "named                            RUNNING",
        "wazuh-agent                      RUNNING",
        "techvault.local.\t86400\tIN\tSOA",
        "_ldap._tcp.techvault.local.",
        "22.1.20.172.in-addr.arpa.",
        "CapEff:",
        "bind:x:102:103",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_dns_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)

    assert counts == dict(computed)
    assert sum(counts.values()) == len(vulnerabilities) == TRIVY_FINDING_COUNT
    assert counts == {"LOW": 22, "MEDIUM": 58}
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)


def test_dns_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert trivy_sbom["metadata"]["component"]["name"].startswith("aptl-dns")
    assert syft_version["application"] == "syft"
    assert [
        prop
        for component in syft_sbom["components"]
        for prop in component.get("properties", [])
        if prop["name"].startswith("syft:location:")
    ] == []


def test_dns_osquery_evidence_records_requested_tables_and_limits():
    expected_tables = {
        "apt_sources",
        "docker_containers",
        "docker_images",
        "installed_applications",
        "listening_ports",
        "processes",
        "programs",
    }
    table_files = {
        path.name.removeprefix("osquery-").removesuffix(".json").replace("-", "_")
        for path in EVIDENCE_DIR.glob("osquery-*.json")
    }
    assert expected_tables <= table_files

    processes = _json_file("osquery-processes.json")
    process_names = {row["name"] for row in processes["rows"]}
    assert {"supervisord", "named", "wazuh-agent.sh"} <= process_names

    listening_ports = _json_file("osquery-listening-ports.json")
    assert any(row["port"] == "53" for row in listening_ports["rows"])
    assert any(row["port"] == "953" for row in listening_ports["rows"])

    docker_containers = _json_file("osquery-docker-containers.json")
    assert docker_containers["rows"][0]["name"] == "/aptl-dns"

    for name in ("installed-applications", "programs"):
        payload = _json_file(f"osquery-{name}.json")
        assert payload["status"] == "unavailable"
        assert payload["rows"] == []


def test_techvault_sdl_encodes_dns_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    dns = data["nodes"]["dns"]
    runtime = dns["runtime"]
    build = dns["source"]["build"]

    assert dns["source"]["name"] == "aptl-dns"
    assert dns["source"]["version"] == IMAGE_DIGEST
    assert dns["os_version"] == "Ubuntu 22.04.5 LTS"
    assert build["base_image"] == "ubuntu:22.04"
    assert build["dockerfile_path"] == "containers/dns/Dockerfile"
    assert len(build["instructions"]) == 16
    assert len(build["layers"]) == 20
    assert len(build["source_inputs"]) == 10
    assert len(build["copied_sources"]) == 8
    assert build["config"]["command"] == [
        "/usr/bin/supervisord",
        "-n",
        "-c",
        "/etc/supervisor/supervisord.conf",
    ]
    assert {"port": 53, "protocol": "tcp", "name": "dns-tcp"} in dns["services"]
    assert {"port": 53, "protocol": "udp", "name": "dns-udp"} in dns["services"]

    assert len(runtime["mounts"]) == 26
    assert len(runtime["packages"]) == PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["environment"]) == 9
    assert len(runtime["processes"]) == 9, (
        "9 = the original 8 wazuh+named processes + the PID 1 supervisord entry "
        "added when ACES PR #458 retired the singular runtime.process field "
        "(the supervisord identity had previously lived ONLY in runtime.process "
        "for dns; the migration must move it into runtime.processes or it is "
        "silently dropped)."
    )
    assert "process" not in runtime, (
        "ACES PR #458 removed runtime.process; PID 1 supervisord identity now "
        "lives inside runtime.processes (looked up by name, not index — the dns "
        "list is not PID-sorted)."
    )
    supervisord_processes = [p for p in runtime["processes"] if p["name"] == "supervisord"]
    assert len(supervisord_processes) == 1, "supervisord must appear exactly once in runtime.processes"
    supervisord = supervisord_processes[0]
    assert supervisord["pid"] == 1
    assert supervisord["role"] == "primary"
    assert supervisord["user"] == "root"
    assert runtime["linux_capabilities"]["add"] == ["CAP_NET_ADMIN"]
    assert runtime["operational_policy"]["restart"] == "unless_stopped"
    assert runtime["health"]["status"] == "healthy"
    assert len(runtime["health"]["log"]) == 5

    endpoints = {endpoint["network"]: endpoint for endpoint in runtime["network"]["endpoints"]}
    assert endpoints["dmz-net"]["ip_address"] == "172.20.1.22"
    assert endpoints["internal-net"]["ip_address"] == "172.20.2.27"
    assert endpoints["security-net"]["ip_address"] == "172.20.0.25"
    published = {
        (port["protocol"], port["host_ip"], port["host_port"], port["container_port"])
        for port in runtime["network"]["published_ports"]
    }
    assert published == {
        ("tcp", "0.0.0.0", 5353, 53),
        ("tcp", "::", 5353, 53),
        ("udp", "0.0.0.0", 5353, 53),
        ("udp", "::", 5353, 53),
    }

    dns_service = runtime["dns_services"][0]
    assert dns_service["dns_service_id"] == "techvault-bind"
    assert dns_service["implementation"] == "bind"
    assert dns_service["version"] == BIND_VERSION
    assert dns_service["roles"] == [
        "authoritative",
        "recursive_resolver",
        "forwarding_resolver",
    ]
    assert dns_service["dynamic_update"]["enabled"] is False
    assert dns_service["resolver_policy"]["recursion_enabled"] is True
    assert dns_service["resolver_policy"]["allow_recursion"] == ["172.20.0.0/16"]
    assert [f["address"] for f in dns_service["resolver_policy"]["forwarders"]] == [
        "8.8.8.8",
        "8.8.4.4",
    ]
    assert dns_service["resolver_policy"]["dnssec_validation"] == "disabled"

    zones = {zone["zone_id"]: zone for zone in dns_service["zones"]}
    assert len(zones["techvault-local"]["rrsets"]) == FORWARD_RRSET_COUNT
    assert len(zones["reverse-20-172"]["rrsets"]) == REVERSE_RRSET_COUNT
    forward = {rrset["rrset_id"]: rrset for rrset in zones["techvault-local"]["rrsets"]}
    reverse = {rrset["rrset_id"]: rrset for rrset in zones["reverse-20-172"]["rrsets"]}
    assert forward["a-ns1"]["records"][0]["address"] == "172.20.1.22"
    assert forward["a-webapp"]["records"][0]["address"] == "172.20.1.20"
    assert forward["forward-root-mx"]["records"][0]["mx"]["exchange"] == "mail.techvault.local."
    assert forward["srv-ldap-tcp"]["records"][0]["srv"]["port"] == 389
    assert reverse["ptr-22-1-20-172-in-addr-arpa"]["records"][0]["target"] == "ns1.techvault.local."
    assert zones["techvault-local"]["transfer"]["axfr_enabled"] is True

    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert filesystem["/etc/bind/named.conf"]["content_digest"] == (
        "3df85c5e388295b0e321598c9932a78bfb18e47315263c6990e9e36cb1b62ee7"
    )
    assert filesystem["/var/log/named/query.log"]["stability"] == "log"
    assert filesystem["/var/log/named"]["entry_type"] == "directory"


def test_techvault_sdl_parses_and_compiles_with_dns_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.dns"].spec["node"]
    runtime = node["runtime"]
    dns_service = runtime["dns_services"][0]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["network"]["endpoints"]) == 3
    assert len(runtime["network"]["published_ports"]) == 4
    assert runtime["container"]["runtime_name"] == "runc"
    assert dns_service["dns_service_id"] == "techvault-bind"
    assert len(dns_service["zones"][0]["rrsets"]) == FORWARD_RRSET_COUNT
    assert len(dns_service["zones"][1]["rrsets"]) == REVERSE_RRSET_COUNT


def test_dns_sdl_filesystem_inventory_matches_evidence_paths():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    encoded = {
        entry["path"]: entry
        for entry in data["nodes"]["dns"]["runtime"]["filesystem_inventory"]
    }
    for line in (EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines():
        path = line.split(" ", 4)[4]
        assert path in encoded


def test_dns_runtime_local_identity_matches_passwd_and_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    local_identity = data["nodes"]["dns"]["runtime"]["local_identity"]
    encoded_users = {user["username"]: user for user in local_identity["users"]}
    encoded_groups = {group["name"]: group for group in local_identity["groups"]}

    assert len(encoded_users) == len(_runtime_baseline_section("users"))
    assert len(encoded_groups) == len(_runtime_baseline_section("groups"))
    assert encoded_users["bind"]["uid"] == 102
    assert encoded_users["wazuh"]["home"] == "/var/ossec"
    assert encoded_groups["bind"]["gid"] == 103
    assert local_identity["sudo_rules"] == []


def test_techvault_sdl_dns_content_accounts_relationships_and_parity():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content = data["content"]
    accounts = data["accounts"]
    relationships = data["relationships"]
    parity = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in parity["rows"]}

    assert "dns-file-etc-bind-named-conf" in content
    assert "dns-file-etc-bind-zones-techvault-local-zone" in content
    assert content["dns-file-var-log-named-query-log"]["source"]["version"].startswith("sha256:")
    assert accounts["dns-local-bind"]["disabled"] is True
    assert accounts["dns-local-wazuh"]["home"] == "/var/ossec"
    forward = relationships["dns-forwards-wazuh"]
    assert forward["target"] == "wazuh-manager"
    assert "properties" not in forward, (
        "PR #458: the typed forwarding_edge payload replaces the legacy "
        "properties.protocol/log_paths prose."
    )
    assert forward["forwarding_edge"]["forwarder_ref"] == "dns-wazuh-agent"

    dns_runtime = data["nodes"]["dns"]["runtime"]
    forwarding_agents = {
        agent["forwarding_agent_id"]: agent
        for agent in dns_runtime.get("forwarding_agents", [])
    }
    assert "dns-wazuh-agent" in forwarding_agents, (
        "PR #458: dns runs the Wazuh agent in-process (ADR-020), so the "
        "forwarder must be encoded under nodes.dns.runtime.forwarding_agents."
    )
    agent = forwarding_agents["dns-wazuh-agent"]
    assert agent["implementation"] == "wazuh_agent"
    assert agent["agent_kind"] == "log_forwarder"
    assert agent["buffer_policy"]["buffer_policy_id"] == "dns-wazuh-agent-buffer"
    assert 1514 in {target["ingestion_port"] for target in agent["ship_targets"]}

    assert relationships["ad-forwards-dns"]["target"] == "dns"
    assert rows["scen.techvault.dns-inventory"]["category"] == "aces_sdl"
    assert "nodes.dns.runtime.dns_services" in rows["scen.techvault.dns-inventory"]["aces_target"]
    assert rows["compose.service.dns"]["category"] == "aces_sdl"
    assert rows["compose.profile.dns"]["category"] == "aptl_backend_responsibility"
