"""Checks for the SCN-010 reverse steady-state inventory bundle."""

from pathlib import Path
import gzip
import hashlib
import json
import lzma
import re

import pytest

from tests.techvault_sdl import load_legacy_techvault_sdl

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)

pytestmark = pytest.mark.integration


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "reverse"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:7ba01e2a24863fd18fff96a3944fe4d31876d24953fb4f6410334ff36f27a192"
IMAGE_DIGEST = "aptl-reverse@sha256:7ba01e2a24863fd18fff96a3944fe4d31876d24953fb4f6410334ff36f27a192"
RUNTIME_PACKAGE_COUNT = 506
TRIVY_FINDING_COUNT = 67
FILESYSTEM_TREE_ROW_COUNT = 221
SDL_FILESYSTEM_ENTRY_COUNT = 221
LOCAL_IDENTITY_USER_COUNT = 27
LOCAL_IDENTITY_GROUP_COUNT = 48
DOCKER_HISTORY_ROW_COUNT = 35
IMAGE_INSTRUCTION_COUNT = 31
IMAGE_LAYER_COUNT = 35
SOURCE_INPUT_COUNT = 13
RUNTIME_PROCESS_COUNT = 13
RUNTIME_ENV_COUNT = 4
MOUNT_COUNT = 31
SERVICE_MANAGER_UNIT_COUNT = 113
LEDGER_FACT_COUNT = 20

REQUIRED_EVIDENCE_FILES = {
    "apt-repositories.txt",
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.reverse.json",
    "docker-buildx-imagetools.image.err",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.reverse.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.reverse-home.json",
    "docker-volume.reverse_logs.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-sensitive-paths.txt",
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
    "reverse-tools-state.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
    "systemd-units.txt",
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


def _section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z0-9][a-z0-9-]*--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def test_reverse_note_declares_scope_and_realization_caveats():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #338",
        "aptl-reverse",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run\n`aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "No known ACES expressivity gap remains",
        "nodes.techvault.reverse",
        "reverse-forwards-wazuh",
        "first-boot",
        "floss",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"reverse inventory note missing scope markers: {missing}"


def test_reverse_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "reverse-tools-state.txt",
        "observer-discovery.wazuh-manager.txt",
        "filesystem-tree.txt.gz",
        "filesystem-checksums.txt.xz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_reverse_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 338
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["reverse.provisioning.first-boot"] == "encoded_with_caveat"
    assert dispositions["reverse.relationship.forwards-wazuh"] == "encoded_with_caveat"
    assert dispositions["reverse.ssh.service"] == "encoded"


def test_reverse_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_reverse_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_reverse_evidence_sha256_manifest_matches_files():
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


def test_reverse_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_reverse_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_reverse_runtime_evidence_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["Config"]["Entrypoint"] == ["/usr/local/bin/entrypoint.sh"]
    assert image["Config"]["Cmd"] == ["/usr/sbin/init"]
    assert container["HostConfig"]["Memory"] == 2147483648
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert container["HostConfig"]["CgroupnsMode"] == "host"
    assert set(container["HostConfig"]["CapAdd"]) == {"CAP_SYS_ADMIN", "CAP_SYS_NICE", "CAP_SYS_RESOURCE"}

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT


def test_reverse_trivy_counts_match_severity_breakdown():
    counts = {row["severity"]: row["count"] for row in _json_file("trivy-vulnerability-counts.json")}
    assert counts == {"LOW": 32, "MEDIUM": 35}
    assert sum(counts.values()) == TRIVY_FINDING_COUNT


def test_reverse_ssh_listener_published_and_locked_down():
    rows = _json_file("osquery-listening-ports.json")["rows"]
    ssh = [r for r in rows if r["port"] == "22"]
    assert ssh, "SSH listener (22) must be present"
    sshd_cfg = {line.split(" ", 1)[0]: (line.split(" ", 1)[1] if " " in line else "") for line in _section("sshd-effective-config")}
    assert sshd_cfg.get("passwordauthentication") == "no"
    assert sshd_cfg.get("permitrootlogin") == "no"
    assert sshd_cfg.get("pubkeyauthentication") == "yes"


def test_reverse_observer_and_participant_vantages():
    observer = (EVIDENCE_DIR / "observer-discovery.wazuh-manager.txt").read_text(encoding="utf-8")
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "reverse" in observer
    assert "Active" in observer
    assert "Network is unreachable" in kali


def test_reverse_first_boot_state_records_toolchain():
    state = (EVIDENCE_DIR / "reverse-tools-state.txt").read_text(encoding="utf-8")
    assert "/usr/local/bin/radare2" in state
    assert ".reverse_tools_installed" in state


def test_techvault_sdl_encodes_reverse_node(legacy_scenario):
    node = legacy_scenario["nodes"]["reverse"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["name"] == "aptl-reverse"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Ubuntu 22.04.5 LTS"
    assert build["base_image"] == "ubuntu:22.04"
    assert build["dockerfile_path"] == "containers/reverse/Dockerfile"
    assert len(build["instructions"]) == IMAGE_INSTRUCTION_COUNT
    assert len(build["layers"]) == IMAGE_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert build["attestation"]["status"] == "absent"

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == SDL_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert len(runtime["mounts"]) == MOUNT_COUNT
    assert len(runtime["service_manager_units"]) == SERVICE_MANAGER_UNIT_COUNT

    caps = runtime["linux_capabilities"]
    assert set(caps["add"]) == {"CAP_SYS_ADMIN", "CAP_SYS_NICE", "CAP_SYS_RESOURCE"}
    assert runtime["container"]["namespaces"]["cgroup"] == "host"

    network = runtime["network"]
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.27"
    published = {(p["host_port"], p["container_port"]) for p in network["published_ports"]}
    assert (2027, 22) in published

    ssh = runtime["ssh_servers"][0]
    assert ssh["password_authentication"] is False
    assert ssh["pubkey_authentication"] is True

    processes = {proc["name"] for proc in runtime["processes"]}
    assert "systemd" in processes
    assert {"wazuh-agentd", "falco", "sshd"} <= processes

    sudo = runtime["local_identity"]["sudo_rules"]
    assert any(rule["principal"] == "labadmin" and rule["nopasswd"] for rule in sudo)


def test_techvault_sdl_encodes_reverse_forwarding_and_relationship(legacy_scenario):
    node = legacy_scenario["nodes"]["reverse"]
    agents = {a["forwarding_agent_id"]: a for a in node["runtime"]["forwarding_agents"]}
    assert "reverse-wazuh-agent" in agents
    assert "reverse-rsyslog-forwarder" in agents
    assert agents["reverse-wazuh-agent"]["implementation"] == "wazuh_agent"
    assert agents["reverse-rsyslog-forwarder"]["implementation"] == "rsyslog"

    rel = legacy_scenario["relationships"]["reverse-forwards-wazuh"]
    assert rel["source"] == "reverse"
    assert rel["target"] == "wazuh-manager"
    assert rel["forwarding_edge"]["forwarder_ref"] == "reverse-wazuh-agent"


def test_techvault_sdl_reverse_features_and_vulnerability(legacy_scenario):
    node = legacy_scenario["nodes"]["reverse"]
    # The legacy loader strips the "techvault." namespace prefix.
    assert set(node["features"]) == {
        "reverse-rsyslog-forwarding",
        "reverse-wazuh-agent",
        "reverse-falco-agent",
    }
    assert node["vulnerabilities"] == ["reverse-nopasswd-sudo"]


def test_reverse_local_accounts_are_encoded(legacy_scenario):
    accounts = legacy_scenario["accounts"]
    reverse_accounts = {
        account["username"]
        for name, account in accounts.items()
        if name.startswith("reverse-local-")
    }
    passwd_usernames = {line.split(":", maxsplit=1)[0] for line in _section("users")}
    assert passwd_usernames <= reverse_accounts
    assert accounts["reverse-local-root"]["shell"] == "/bin/bash"
    # The legacy loader strips the "techvault." namespace prefix from node refs.
    assert accounts["reverse-local-labadmin"]["node"] == "reverse"
    assert "sudo" in accounts["reverse-local-labadmin"]["groups"]


def test_techvault_sdl_compiles_with_reverse_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.reverse"].spec["node"]
    runtime = node["runtime"]
    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(node["source"]["build"]["instructions"]) == IMAGE_INSTRUCTION_COUNT
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["service_manager_units"]) == SERVICE_MANAGER_UNIT_COUNT
    assert runtime["container"]["runtime_name"] == "runc"
    assert set(runtime["linux_capabilities"]["add"]) == {"CAP_SYS_ADMIN", "CAP_SYS_NICE", "CAP_SYS_RESOURCE"}


def test_parity_inventory_cites_reverse_inventory():
    import yaml

    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text(encoding="utf-8"))["rows"]}
    row = rows["scen.techvault.reverse-inventory"]
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "nodes.techvault.reverse" in row["aces_target"]
    assert "docs/aces/inventory/reverse/" in row["validation_evidence"]
    assert "tests/test_reverse_inventory.py" in row["validation_evidence"]
