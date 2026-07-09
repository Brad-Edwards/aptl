"""Checks for the SCN-010 thehive steady-state inventory bundle."""

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
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "thehive"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:ba3212a89be79de6ec8e6e66b84f3c0801c3b8d726aacc767ad6257030df7a13"
IMAGE_DIGEST = "strangebee/thehive@sha256:ba3212a89be79de6ec8e6e66b84f3c0801c3b8d726aacc767ad6257030df7a13"
PLAY_SECRET_FIXTURE = "aptl-thehive-lab-secret-key-2024-purple"
HTTPS_KEYSTORE_PASSWORD = "kInP5SyV3kLmdbLVVMP1wgSQtzkEv2UM"
TH_CORTEX_KEYS = "aptlcortexlabapikey2026purple"
THEHIVE_SANDBOX_KEY = "/var/run/docker/netns/bfb6b9ee439f"
THEHIVE_KEYSTORE_SHA256 = "cad6bfad83329a1b6a69db3940429fe9281961f88ef7e271e1608449858f89bc"
RUNTIME_PACKAGE_COUNT = 126
TRIVY_FINDING_COUNT = 376
FILESYSTEM_TREE_ROW_COUNT = 556
SDL_FILESYSTEM_ENTRY_COUNT = 556
LOCAL_IDENTITY_USER_COUNT = 19
LOCAL_IDENTITY_GROUP_COUNT = 39
DOCKER_HISTORY_ROW_COUNT = 19
RUNTIME_PROCESS_COUNT = 1
RUNTIME_ENV_COUNT = 6
LEDGER_FACT_COUNT = 19

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.thehive.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.thehive.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.thehive_data.json",
    "docker-volume.thehive_index.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
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
    "participant-discovery.kali.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
    "thehive-state.txt",
    "trivy-sbom.cyclonedx.json.gz",
    "trivy-version.txt",
    "trivy-vulnerabilities.json.gz",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}

SUPPRESSION_PLACEHOLDERS = (
    "<REDACTED",
    "<OMITTED",
    "operator_secret",
    "value withheld",
    "content excluded",
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


def test_thehive_note_declares_scope_and_realization_caveats():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #350",
        "aptl-thehive",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run\n`aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "No known ACES expressivity gap remains",
        "nodes.techvault.thehive",
        "local Lucene",
        "thehive-connects-cassandra",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"thehive inventory note missing scope markers: {missing}"


def test_thehive_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "thehive-state.txt",
        "filesystem-tree.txt.gz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_thehive_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 350
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["thehive.application.thehive-web"] == "encoded"
    assert dispositions["thehive.secret.play-application-secret"] == "encoded_with_caveat"
    assert dispositions["thehive.relationship.connects-cassandra"] == "encoded_with_caveat"


def test_thehive_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_thehive_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_thehive_evidence_sha256_manifest_matches_files():
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


def test_thehive_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_thehive_evidence_has_no_secret_suppression_placeholders():
    forbidden = re.compile("|".join(re.escape(marker) for marker in SUPPRESSION_PLACEHOLDERS), re.IGNORECASE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Evidence still contains secret suppression placeholders: {offenders}"


def test_thehive_runtime_evidence_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["RepoDigests"][0] == IMAGE_DIGEST
    assert container["HostConfig"]["Memory"] == 1073741824
    assert container["NetworkSettings"]["SandboxKey"] == THEHIVE_SANDBOX_KEY
    # The Play application secret is a committed fixture on the container command.
    assert PLAY_SECRET_FIXTURE in container["Config"]["Cmd"]
    assert f"HTTPS_KEYSTORE_PASSWORD={HTTPS_KEYSTORE_PASSWORD}" in container["Config"]["Env"]
    assert f"TH_CORTEX_KEYS={TH_CORTEX_KEYS}" in container["Config"]["Env"]

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT


def test_thehive_runtime_evidence_captures_scenario_secret_values():
    runtime = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    checksums = _evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz")
    state = (EVIDENCE_DIR / "thehive-state.txt").read_text(encoding="utf-8")

    assert f"HTTPS_KEYSTORE_PASSWORD={HTTPS_KEYSTORE_PASSWORD}" in runtime
    assert f"TH_CORTEX_KEYS={TH_CORTEX_KEYS}" in runtime
    assert f"{THEHIVE_KEYSTORE_SHA256}  /etc/thehive/keystore.p12" in checksums
    assert "password = ${?HTTPS_KEYSTORE_PASSWORD}" in state


def test_thehive_trivy_counts_match_severity_breakdown():
    counts = {row["severity"]: row["count"] for row in _json_file("trivy-vulnerability-counts.json")}
    assert counts == {"CRITICAL": 9, "HIGH": 58, "MEDIUM": 152, "LOW": 156, "UNKNOWN": 1}
    assert sum(counts.values()) == TRIVY_FINDING_COUNT


def test_thehive_uses_local_lucene_not_es():
    state = (EVIDENCE_DIR / "thehive-state.txt").read_text(encoding="utf-8")
    assert "index.search.backend = lucene" in state


def test_thehive_https_listener_published():
    rows = _json_file("osquery-listening-ports.json")["rows"]
    ports = {row["port"] for row in rows if row["port"] not in ("0", "", None) and not row["address"].startswith("127.0.0.11")}
    assert "9000" in ports


def test_techvault_sdl_encodes_thehive_node(legacy_scenario):
    node = legacy_scenario["nodes"]["thehive"]
    runtime = node["runtime"]

    assert node["source"]["name"] == "strangebee/thehive"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Debian GNU/Linux 12 (bookworm)"

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == SDL_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT

    network = runtime["network"]
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.18"
    published = {(p["host_port"], p["container_port"]) for p in network["published_ports"]}
    assert (9000, 9000) in published

    listener_ports = {listener["port"] for listener in runtime["service_listeners"]}
    assert 9000 in listener_ports

    # The Play application secret fixture is kept verbatim on the container command.
    assert PLAY_SECRET_FIXTURE in runtime["container"]["command"]

    # The generated keystore password is captured as scenario content.
    env = {item["name"]: item for item in runtime["environment"]}
    assert env["HTTPS_KEYSTORE_PASSWORD"]["value_classification"] == "secret_fixture"
    assert env["HTTPS_KEYSTORE_PASSWORD"]["value"] == HTTPS_KEYSTORE_PASSWORD
    assert env["TH_CORTEX_KEYS"]["value_classification"] == "secret_fixture"
    assert env["TH_CORTEX_KEYS"]["value"] == TH_CORTEX_KEYS


def test_techvault_sdl_encodes_thehive_application(legacy_scenario):
    apps = legacy_scenario["nodes"]["thehive"]["runtime"]["applications"]
    assert len(apps) == 1
    app = apps[0]
    assert app["protocol"] == "https"
    assert "TheHive" in app["name"]
    assert any(route["path"] == "/api/status" for route in app["routes"])


def test_techvault_sdl_encodes_thehive_cassandra_relationship_only(legacy_scenario):
    relationships = legacy_scenario["relationships"]
    rel = relationships["thehive-connects-cassandra"]
    assert rel["source"] == "thehive"
    assert rel["target"] == "thehive-cassandra"
    assert rel["properties"]["protocol"] == "cql"
    # TheHive uses local Lucene, not ES — there must be NO thehive->es relationship.
    assert "thehive-connects-es" not in relationships


def test_techvault_sdl_compiles_with_thehive_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.thehive"].spec["node"]
    runtime = node["runtime"]
    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["applications"]) == 1
    assert runtime["container"]["runtime_name"] == "runc"


def test_parity_inventory_cites_thehive_inventory():
    import yaml

    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text(encoding="utf-8"))["rows"]}
    row = rows["scen.techvault.thehive-inventory"]
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "nodes.techvault.thehive" in row["aces_target"]
    assert "docs/aces/inventory/thehive/" in row["validation_evidence"]
    assert "tests/test_thehive_inventory.py" in row["validation_evidence"]
