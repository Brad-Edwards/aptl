"""Checks for the SCN-010 misp-suricata-sync steady-state inventory bundle."""

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
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "misp-suricata-sync"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:f2e12bfa2a1fb8771c01a54880154e4f0d90360f98bba592accf23bdda8c276e"
IMAGE_DIGEST = "aptl-misp-suricata-sync@sha256:f2e12bfa2a1fb8771c01a54880154e4f0d90360f98bba592accf23bdda8c276e"
# The disclosed MISP admin API key fixture (nodes.techvault.misp ADMIN_KEY);
# it must appear in the SDL encoding and must NOT appear in committed evidence.
MISP_API_KEY_FIXTURE = "JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw"
RUNTIME_PACKAGE_COUNT = 110
TRIVY_FINDING_COUNT = 220
FILESYSTEM_TREE_ROW_COUNT = 244
FILESYSTEM_CHECKSUM_COUNT = 209
SDL_FILESYSTEM_ENTRY_COUNT = 22
LOCAL_IDENTITY_USER_COUNT = 18
LOCAL_IDENTITY_GROUP_COUNT = 38
DOCKER_HISTORY_ROW_COUNT = 16
IMAGE_INSTRUCTION_COUNT = 7
IMAGE_LAYER_COUNT = 16
SOURCE_INPUT_COUNT = 9
RUNTIME_PROCESS_COUNT = 1
RUNTIME_ENV_COUNT = 15
SOFTWARE_COMPONENT_COUNT = 2
LEDGER_FACT_COUNT = 23

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.misp-suricata-sync.json",
    "docker-buildx-imagetools.image.err",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.misp-suricata-sync.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.suricata_command_socket.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
    "language-manifests.txt",
    "observer-discovery.suricata.txt",
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
    "sync-service-state.txt",
    "trivy-sbom.cyclonedx.json.gz",
    "trivy-version.txt",
    "trivy-vulnerabilities.json.gz",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
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


def test_misp_suricata_sync_note_declares_scope_and_realization_caveats():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #349",
        "aptl-misp-suricata-sync",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run\n`aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "No known ACES expressivity gap remains",
        "nodes.techvault.misp-suricata-sync",
        "ADR-019",
        "misp-suricata-sync-queries-misp-api",
        "misp-suricata-sync-updates-suricata-rules",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"misp-suricata-sync inventory note missing scope markers: {missing}"


def test_misp_suricata_sync_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        'yq -o=json \'.services."misp-suricata-sync"\'',
        "sync-service-state.txt",
        "observer-discovery.suricata.txt",
        "filesystem-tree.txt.gz",
        "filesystem-checksums.txt.xz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_misp_suricata_sync_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 349
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["misp-suricata-sync.secret.misp-api-key-fixture"] == "encoded_with_caveat"
    assert dispositions["misp-suricata-sync.relationship.updates-suricata-rules"] == "encoded"
    assert dispositions["misp-suricata-sync.runtime.service-listeners"] == "encoded_with_caveat"


def test_misp_suricata_sync_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_misp_suricata_sync_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_misp_suricata_sync_evidence_sha256_manifest_matches_files():
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


def test_misp_suricata_sync_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_misp_suricata_sync_evidence_does_not_commit_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"
    # The MISP admin API key fixture must never appear in committed evidence
    # (it is carried only in the SDL secret-fixture encoding).
    leaked = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and MISP_API_KEY_FIXTURE in _evidence_text(path)
    ]
    assert not leaked, f"MISP API key fixture leaked into evidence: {leaked}"


def test_misp_suricata_sync_runtime_evidence_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["Config"]["Entrypoint"] == ["aptl-misp-suricata-sync"]
    assert container["HostConfig"]["Memory"] == 134217728
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert container["HostConfig"]["CapAdd"] in (None, [])

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz").splitlines()) == FILESYSTEM_CHECKSUM_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_runtime_baseline_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_runtime_baseline_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT


def test_misp_suricata_sync_trivy_counts_match_severity_breakdown():
    counts = {row["severity"]: row["count"] for row in _json_file("trivy-vulnerability-counts.json")}
    assert counts == {"CRITICAL": 2, "HIGH": 19, "MEDIUM": 73, "LOW": 125, "UNKNOWN": 1}
    assert sum(counts.values()) == TRIVY_FINDING_COUNT


def test_misp_suricata_sync_listeners_show_no_network_service():
    rows = _json_file("osquery-listening-ports.json")["rows"]
    network_ports = [
        row for row in rows
        if row["port"] not in ("0", "", None) and not row["address"].startswith("127.0.0.11")
    ]
    assert network_ports == [], f"Sync service must expose no network listener; saw {network_ports}"


def test_misp_suricata_sync_observer_and_participant_vantages():
    observer = (EVIDENCE_DIR / "observer-discovery.suricata.txt").read_text(encoding="utf-8")
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "misp-iocs.rules" in observer
    assert "suricata-command.socket" in observer
    assert "Network is unreachable" in kali


def test_misp_suricata_sync_state_records_rules_and_socket():
    state = (EVIDENCE_DIR / "sync-service-state.txt").read_text(encoding="utf-8")
    assert "misp-iocs.rules" in state
    assert "ioc_count=0" in state
    assert "suricata-command.socket" in state
    assert "tag_filter=aptl:enforce" in state


def test_techvault_sdl_encodes_misp_suricata_sync_node(legacy_scenario):
    node = legacy_scenario["nodes"]["misp-suricata-sync"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["name"] == "aptl-misp-suricata-sync"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Debian GNU/Linux 13 (trixie)"
    assert build["base_image"] == "python:3.11-slim"
    assert build["dockerfile_path"] == "containers/misp-suricata-sync/Dockerfile"
    assert len(build["instructions"]) == IMAGE_INSTRUCTION_COUNT
    assert len(build["layers"]) == IMAGE_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert build["source_inputs"][0]["source_path"] == "pyproject.toml"
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

    env = {item["name"]: item for item in runtime["environment"]}
    assert env["MISP_URL"]["value"] == "https://misp"
    assert env["IOC_TAG_FILTER"]["value"] == "aptl:enforce"
    assert env["SYNC_INTERVAL_SECONDS"]["value"] == "300"
    assert env["RULES_OUT_PATH"]["value"] == "/var/lib/suricata/rules/misp/misp-iocs.rules"
    assert env["MISP_API_KEY"]["value_classification"] == "secret_fixture"
    assert env["MISP_API_KEY"]["value"] == MISP_API_KEY_FIXTURE
    assert env["GPG_KEY"]["value_classification"] == "secret_fixture"

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert len(mounts) == 3
    assert mounts["/var/run/suricata"]["source"] == "aptl_suricata_command_socket"
    assert mounts["/var/lib/suricata/rules/misp"]["source"] == ".aptl/suricata/rules/misp"
    assert mounts["/var/lib/suricata/rules/misp"]["read_only"] is False
    assert mounts["/etc/lab-ca/lab-ca.pem"]["read_only"] is True

    caps = runtime["linux_capabilities"]
    assert "CAP_NET_ADMIN" not in caps["effective"]
    assert caps["add"] == []

    assert runtime["service_listeners"] == []
    network = runtime["network"]
    assert network["published_ports"] == []
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.19"
    assert endpoint["aliases"] == ["aptl-misp-suricata-sync", "misp-suricata-sync"]

    assert runtime["processes"][0]["name"] == "aptl-misp-suricata-sync"
    assert runtime["processes"][0]["pid"] == 1

    fs = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert fs["/var/lib/suricata/rules/misp/misp-iocs.rules"]["stability"] == "runtime_created"
    assert fs["/var/run/suricata/suricata-command.socket"]["entry_type"] == "socket"
    assert "/etc/lab-ca/lab-ca.pem" in fs
    components = {c["component_id"]: c for c in runtime["software_components"]}
    assert components["aptl-misp-suricata-sync"]["version"] == "0.1.0"
    assert components["python"]["version"].startswith("3.11.")


def test_techvault_sdl_encodes_misp_suricata_sync_relationships(legacy_scenario):
    relationships = legacy_scenario["relationships"]

    api = relationships["misp-suricata-sync-queries-misp-api"]
    assert api["source"] == "misp-suricata-sync"
    assert api["properties"]["auth_method"] == "api_key"
    assert api["properties"]["tls_verification"] == "lab_ca"

    handoff = relationships["misp-suricata-sync-updates-suricata-rules"]
    assert handoff["source"] == "misp-suricata-sync"
    assert handoff["target"] == "suricata"
    assert handoff["properties"]["protocol"] == "unix-socket"
    assert handoff["properties"]["socket_path"] == "/var/run/suricata/suricata-command.socket"
    assert handoff["properties"]["rules_path"] == "/var/lib/suricata/rules/misp/misp-iocs.rules"


def test_misp_suricata_sync_runtime_local_identity_matches_passwd_and_group_evidence(legacy_scenario):
    local_identity = legacy_scenario["nodes"]["misp-suricata-sync"]["runtime"]["local_identity"]
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


def test_misp_suricata_sync_local_accounts_are_encoded(legacy_scenario):
    accounts = legacy_scenario["accounts"]
    account_usernames = {
        account["username"]
        for name, account in accounts.items()
        if name.startswith("misp-suricata-sync-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames <= account_usernames
    assert accounts["misp-suricata-sync-local-root"]["shell"] == "/bin/bash"
    assert accounts["misp-suricata-sync-local-root"]["node"] == "misp-suricata-sync"
    assert accounts["misp-suricata-sync-local-nobody"]["disabled"] is True


def test_techvault_sdl_compiles_with_misp_suricata_sync_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.misp-suricata-sync"].spec["node"]
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


def test_parity_inventory_cites_misp_suricata_sync_inventory():
    import yaml

    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text(encoding="utf-8"))["rows"]}
    row = rows["scen.techvault.misp-suricata-sync-inventory"]
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "nodes.techvault.misp-suricata-sync" in row["aces_target"]
    assert "docs/aces/inventory/misp-suricata-sync/" in row["validation_evidence"]
    assert "tests/test_misp_suricata_sync_inventory.py" in row["validation_evidence"]
