"""Checks for the SCN-010 wazuh-sidecar-suricata steady-state inventory bundle."""

import gzip
import hashlib
import json
import lzma
import os
import re
from pathlib import Path

import pytest

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)
from tests.techvault_sdl import load_legacy_techvault_sdl

pytestmark = pytest.mark.integration


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "wazuh-sidecar-suricata"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:1a9c99918f73a234721fe07ccafdcc6c49e1b3784a16ce86cdb2864636345d25"
IMAGE_DIGEST = "aptl-wazuh-sidecar@sha256:1a9c99918f73a234721fe07ccafdcc6c49e1b3784a16ce86cdb2864636345d25"
RUNTIME_PACKAGE_COUNT = 114
TRIVY_FINDING_COUNT = 165
FILESYSTEM_TREE_ROW_COUNT = 200
FILESYSTEM_CHECKSUM_COUNT = 113
SDL_FILESYSTEM_ENTRY_COUNT = 22
LOCAL_IDENTITY_USER_COUNT = 19
LOCAL_IDENTITY_GROUP_COUNT = 39
DOCKER_HISTORY_ROW_COUNT = 10
IMAGE_INSTRUCTION_COUNT = 10
IMAGE_LAYER_COUNT = 10
SOURCE_INPUT_COUNT = 5
RUNTIME_PROCESS_COUNT = 7
RUNTIME_ENV_COUNT = 6
SOFTWARE_COMPONENT_COUNT = 1
LEDGER_FACT_COUNT = 23

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.wazuh-sidecar-suricata.json",
    "docker-buildx-imagetools.image.err",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.wazuh-sidecar-suricata.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.suricata_logs.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
    "language-manifests.txt",
    "observer-discovery.wazuh-manager.txt",
    "os-packages.txt",
    "osquery-apt-sources.json",
    "osquery-docker-containers.json",
    "osquery-docker-images.json",
    "osquery-installed-applications.json",
    "osquery-listening-ports.json",
    "osquery-processes.json",
    "osquery-programs.json",
    "osquery-version.txt",
    "participant-discovery.kali.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
    "trivy-sbom.cyclonedx.json.gz",
    "trivy-version.txt",
    "trivy-vulnerabilities.json.gz",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
    "wazuh-agent-state.txt",
}

RAW_SECRET_PATTERNS = (
    r"BEGIN .*PRIVATE KEY",
    r"-----BEGIN OPENSSH",
)


@pytest.fixture(scope="module")
def legacy_scenario():
    return load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))


@pytest.fixture(scope="module")
def compiled_runtime_model():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    return compile_runtime_model(parse_sdl_file(TECHVAULT_SDL_PATH))


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    if path.suffix == ".xz":
        with lzma.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8", errors="ignore")


def _section(text: str, name: str) -> list[str]:
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[^-\n][^\n]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _runtime_baseline_section(name: str) -> list[str]:
    return _section((EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8"), name)


def _forwarding_agent(scenario: dict, agent_id: str) -> dict:
    for agent in scenario["forwarding_agents"]:
        if agent["forwarding_agent_id"] == agent_id:
            return agent
    raise AssertionError(f"forwarding agent {agent_id} not found")


def test_wazuh_sidecar_suricata_note_declares_scope_and_realization_caveats():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #344",
        "aptl-wazuh-sidecar-suricata",
        "aptl-wazuh-sidecar:local",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run\n`aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "Brad-Edwards/aces#460",
        "No known ACES expressivity gap remains",
        "nodes.techvault.wazuh-sidecar-suricata",
        "forwarding_agents",
        "no CAP_NET_ADMIN",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"wazuh-sidecar-suricata inventory note missing scope markers: {missing}"


def test_wazuh_sidecar_suricata_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        'yq -o=json \'.services."wazuh-sidecar-suricata"\'',
        "wazuh-agent-state.txt",
        "observer-discovery.wazuh-manager.txt",
        "filesystem-tree.txt.gz",
        "filesystem-checksums.txt.xz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_wazuh_sidecar_suricata_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 344
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["wazuh-sidecar-suricata.runtime.linux-capabilities"] == "encoded_with_caveat"
    assert dispositions["wazuh-sidecar-suricata.agent.forwarding-spec"] == "encoded"
    assert dispositions["wazuh-sidecar-suricata.runtime.service-listeners"] == "encoded_with_caveat"


def test_wazuh_sidecar_suricata_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_wazuh_sidecar_suricata_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_wazuh_sidecar_suricata_evidence_sha256_manifest_matches_files():
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
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and path.name != "evidence-sha256sums.txt"
    }
    assert evidence_files <= manifest_entries


def test_wazuh_sidecar_suricata_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_wazuh_sidecar_suricata_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"
    # The in-range agent registration fixture is captured verbatim.
    agent_state = (EVIDENCE_DIR / "wazuh-agent-state.txt").read_text(encoding="utf-8")
    assert (
        "005 aptl-suricata-agent any "
        "ab7796c5102c0338e4d3be3f3879768aac155b662c2699b5e743382a41d71376"
    ) in agent_state


def test_wazuh_sidecar_suricata_runtime_evidence_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["Config"]["Entrypoint"] == ["/opt/aptl/wazuh/wazuh-agent.sh"]
    assert container["HostConfig"]["Memory"] == 268435456
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert container["HostConfig"]["CapAdd"] in (None, [])

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz").splitlines()) == FILESYSTEM_CHECKSUM_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_runtime_baseline_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_runtime_baseline_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT


def test_wazuh_sidecar_suricata_trivy_counts_match_severity_breakdown():
    counts = {row["severity"]: row["count"] for row in _json_file("trivy-vulnerability-counts.json")}
    assert counts == {"CRITICAL": 3, "HIGH": 12, "MEDIUM": 60, "LOW": 85, "UNKNOWN": 5}
    assert sum(counts.values()) == TRIVY_FINDING_COUNT


def test_wazuh_sidecar_suricata_listeners_show_no_network_service():
    rows = _json_file("osquery-listening-ports.json")["rows"]
    network_ports = [
        row for row in rows
        if row["port"] not in ("0", "", None) and not row["address"].startswith("127.0.0.11")
    ]
    assert network_ports == [], f"Sidecar must expose no network listener; saw {network_ports}"


def test_wazuh_sidecar_suricata_observer_and_participant_vantages():
    observer = (EVIDENCE_DIR / "observer-discovery.wazuh-manager.txt").read_text(encoding="utf-8")
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "aptl-suricata-agent" in observer
    assert "Active" in observer
    assert "Network is unreachable" in kali


def test_techvault_sdl_encodes_wazuh_sidecar_suricata_node(legacy_scenario):
    node = legacy_scenario["nodes"]["wazuh-sidecar-suricata"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["name"] == "aptl-wazuh-sidecar"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Debian GNU/Linux 12 (bookworm)"
    assert build["base_image"] == "debian:12-slim"
    assert build["dockerfile_path"] == "containers/wazuh-sidecar/Dockerfile"
    assert len(build["instructions"]) == IMAGE_INSTRUCTION_COUNT
    assert len(build["layers"]) == IMAGE_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert build["source_inputs"][0]["source_path"] == "containers/_wazuh-agent/install.sh"
    assert build["attestation"]["status"] == "absent"

    assert node["services"] == []
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == SDL_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert runtime["local_identity"]["sudo_rules"] == []
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert runtime["software_components"][0]["version"] == "4.12.0"

    env = {item["name"]: item for item in runtime["environment"]}
    assert env["WAZUH_MANAGER"]["value"] == "wazuh.manager"
    assert env["AGENT_NAME"]["value"] == "aptl-suricata-agent"
    assert env["LOG_PATHS"]["value"] == "/logs/eve.json"
    assert env["LOG_FORMAT"]["value"] == "json"
    assert all(item["value_classification"] == "plain" for item in runtime["environment"])

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert mounts["/logs"]["source"] == "aptl_suricata_logs"
    assert mounts["/logs"]["read_only"] is True

    caps = runtime["linux_capabilities"]
    assert "CAP_NET_ADMIN" not in caps["effective"]
    assert caps["add"] == []

    assert runtime["service_listeners"] == []
    network = runtime["network"]
    assert network["published_ports"] == []
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.36"
    assert endpoint["aliases"] == ["aptl-wazuh-sidecar-suricata", "wazuh-sidecar-suricata"]

    processes = {proc["name"] for proc in runtime["processes"]}
    assert {"wazuh-agentd", "wazuh-logcollector", "wazuh-modulesd"} <= processes

    fs = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert fs["/logs/eve.json"]["stability"] == "log"
    assert fs["/var/ossec/etc/client.keys"]["sensitivity"] == "secret_fixture"
    assert fs["/var/ossec/etc/client.keys"]["content_digest"] == (
        "175fb59eb770e611c4f2120f3b5af2fba07268c8bc1d148beec96036337422e4"
    )
    assert "/var/ossec/queue/rids/006" in fs


def test_techvault_sdl_encodes_wazuh_sidecar_suricata_forwarding_and_relationships(legacy_scenario):
    agent = _forwarding_agent(legacy_scenario, "aptl-suricata-wazuh-agent")
    assert agent["implementation"] == "wazuh_agent"
    assert agent["name"] == "aptl-suricata-agent"
    source = agent["sources"][0]
    assert source["location"] == "/logs/eve.json"
    assert source["parse_format"] == "eve_json"
    buffer_policy = agent["buffer_policy"]
    assert buffer_policy["queue_capacity"] == 5000
    assert buffer_policy["eps"] == 500
    assert buffer_policy["crypto"] == "aes"
    assert buffer_policy["reconnect_seconds"] == 60

    relationships = legacy_scenario["relationships"]
    origin = relationships["suricata-logs-forwarded-wazuh"]
    assert origin["forwarding_edge"]["forwarder_ref"] == "aptl-suricata-wazuh-agent"
    assert origin["forwarding_edge"]["parse_format"] == "eve_json"
    assert origin["forwarding_edge"]["protocol"] == "tcp"
    assert origin["forwarding_edge"]["crypto_method"] == "aes"

    realized = relationships["wazuh-sidecar-suricata-forwards-wazuh-manager"]
    assert realized["source"] == "wazuh-sidecar-suricata"
    assert realized["target"] == "wazuh-manager"
    assert realized["forwarding_edge"]["forwarder_ref"] == "aptl-suricata-wazuh-agent"


def test_wazuh_sidecar_suricata_runtime_local_identity_matches_passwd_and_group_evidence(legacy_scenario):
    local_identity = legacy_scenario["nodes"]["wazuh-sidecar-suricata"]["runtime"]["local_identity"]
    encoded_users = {user["username"]: user for user in local_identity["users"]}
    encoded_groups = {group["name"]: group for group in local_identity["groups"]}

    group_rows = {}
    gid_names = {}
    for line in _runtime_baseline_section("groups"):
        name, _password, gid, members = line.split(":")
        member_list = [member for member in members.split(",") if member]
        group_rows[name] = {"gid": int(gid), "members": member_list}
        gid_names[int(gid)] = name

    assert set(encoded_groups) == set(group_rows)
    for name, expected in group_rows.items():
        assert encoded_groups[name]["gid"] == expected["gid"]
        assert encoded_groups[name]["members"] == expected["members"]

    passwd_rows = {}
    for line in _runtime_baseline_section("users"):
        username, _password, uid, gid, gecos, home, shell = line.split(":")
        passwd_rows[username] = {
            "uid": int(uid),
            "primary_gid": int(gid),
            "primary_group": gid_names[int(gid)],
            "home": home,
            "shell": shell,
            "no_login": shell.endswith("nologin"),
        }

    assert set(encoded_users) == set(passwd_rows)
    for username, expected in passwd_rows.items():
        encoded = encoded_users[username]
        for field, value in expected.items():
            assert encoded[field] == value


def test_wazuh_sidecar_suricata_local_accounts_are_encoded(legacy_scenario):
    accounts = legacy_scenario["accounts"]
    account_usernames = {
        account["username"]
        for name, account in accounts.items()
        if name.startswith("wazuh-sidecar-suricata-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames <= account_usernames
    assert accounts["wazuh-sidecar-suricata-local-root"]["shell"] == "/bin/bash"
    assert accounts["wazuh-sidecar-suricata-local-wazuh"]["node"] == "wazuh-sidecar-suricata"
    assert accounts["wazuh-sidecar-suricata-local-wazuh"]["disabled"] is True


def test_techvault_sdl_compiles_with_wazuh_sidecar_suricata_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.wazuh-sidecar-suricata"].spec["node"]
    runtime = node["runtime"]
    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(node["source"]["build"]["instructions"]) == IMAGE_INSTRUCTION_COUNT
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert runtime["container"]["runtime_name"] == "runc"
    assert "CAP_NET_ADMIN" not in runtime["linux_capabilities"]["effective"]


def test_parity_inventory_cites_wazuh_sidecar_suricata_inventory():
    import yaml

    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text(encoding="utf-8"))["rows"]}
    row = rows["scen.techvault.wazuh-sidecar-suricata-inventory"]
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "nodes.techvault.wazuh-sidecar-suricata" in row["aces_target"]
    assert "docs/aces/inventory/wazuh-sidecar-suricata/" in row["validation_evidence"]
    assert "tests/test_wazuh_sidecar_suricata_inventory.py" in row["validation_evidence"]
