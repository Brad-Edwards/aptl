"""Checks for the SCN-010 shuffle-opensearch steady-state inventory bundle."""

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
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "shuffle-opensearch"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:466a49f379bb8889af29d615475e69b7b990898c6987d28470cd7105df9046ff"
IMAGE_DIGEST = "opensearchproject/opensearch@sha256:466a49f379bb8889af29d615475e69b7b990898c6987d28470cd7105df9046ff"
ADMIN_PW_FIXTURE = "StrongPassword123!"
RUNTIME_PACKAGE_COUNT = 110
TRIVY_FINDING_COUNT = 410
FILESYSTEM_TREE_ROW_COUNT = 101
SDL_FILESYSTEM_ENTRY_COUNT = 101
LOCAL_IDENTITY_USER_COUNT = 14
LOCAL_IDENTITY_GROUP_COUNT = 25
DOCKER_HISTORY_ROW_COUNT = 24
RUNTIME_PROCESS_COUNT = 3
RUNTIME_ENV_COUNT = 6
INDEX_COUNT = 24
LEDGER_FACT_COUNT = 20

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.shuffle-opensearch.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.shuffle-opensearch.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.shuffle_opensearch_data.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
    "language-manifests.txt",
    "opensearch-state.txt",
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
    "shuffle-opensearch-index-mappings.json",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
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


def _section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z0-9][a-z0-9-]*--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def test_shuffle_opensearch_note_declares_scope_and_realization_caveats():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #356",
        "aptl-shuffle-opensearch",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run\n`aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "No known ACES expressivity gap remains",
        "nodes.techvault.shuffle-opensearch",
        "shuffle-backend-connects-opensearch",
        "Security plugin",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"shuffle-opensearch inventory note missing scope markers: {missing}"


def test_shuffle_opensearch_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "opensearch-state.txt",
        "filesystem-tree.txt.gz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_shuffle_opensearch_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 356
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["shuffle-opensearch.datastore.opensearch-service"] == "encoded_with_caveat"
    assert dispositions["shuffle-opensearch.runtime.service-listeners"] == "encoded"


def test_shuffle_opensearch_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_shuffle_opensearch_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_shuffle_opensearch_evidence_sha256_manifest_matches_files():
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


def test_shuffle_opensearch_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_shuffle_opensearch_evidence_commits_scenario_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"
    evidence_text = "\n".join(_evidence_text(path) for path in EVIDENCE_DIR.iterdir())
    assert ADMIN_PW_FIXTURE in evidence_text


def test_shuffle_opensearch_runtime_evidence_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["RepoDigests"][0] == IMAGE_DIGEST
    assert container["HostConfig"]["Memory"] == 1073741824

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT


def test_shuffle_opensearch_trivy_counts_match_severity_breakdown():
    counts = {row["severity"]: row["count"] for row in _json_file("trivy-vulnerability-counts.json")}
    assert counts == {"CRITICAL": 2, "HIGH": 180, "MEDIUM": 210, "LOW": 18}
    assert sum(counts.values()) == TRIVY_FINDING_COUNT


def test_shuffle_opensearch_listeners_are_rest_transport_perf():
    rows = _json_file("osquery-listening-ports.json")["rows"]
    ports = {row["port"] for row in rows if row["port"] not in ("0", "", None) and not row["address"].startswith("127.0.0.11")}
    assert {"9200", "9300", "9600"} <= ports


def test_shuffle_opensearch_24_index_mappings_captured():
    mappings = _json_file("shuffle-opensearch-index-mappings.json")
    assert len(mappings) == INDEX_COUNT
    assert "workflow-000001" in mappings
    assert ".opendistro_security" in mappings


def test_shuffle_opensearch_kali_cannot_route():
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "Network is unreachable" in kali


def test_techvault_sdl_encodes_shuffle_opensearch_node(legacy_scenario):
    node = legacy_scenario["nodes"]["shuffle-opensearch"]
    runtime = node["runtime"]

    assert node["source"]["name"] == "opensearchproject/opensearch"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Amazon Linux 2023"

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == SDL_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT

    network = runtime["network"]
    assert network["published_ports"] == []
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.3"

    wildcard_ports = {l["port"] for l in runtime["service_listeners"] if l["scope"] == "wildcard"}
    assert {9200, 9300, 9600} == wildcard_ports
    dns_listeners = [l for l in runtime["service_listeners"] if l["scope"] == "loopback_only"]
    assert {l["address"] for l in dns_listeners} == {"127.0.0.11"}
    assert {l["protocol"] for l in dns_listeners} == {"tcp", "udp"}

    # The data volume holding ALL OpenSearch index state is a typed runtime mount.
    volume_mounts = [m for m in runtime["mounts"] if m["source_kind"] == "volume"]
    assert [(m["target"], m["source"], m["read_only"]) for m in volume_mounts] == [
        ("/usr/share/opensearch/data", "aptl_shuffle_opensearch_data", False)
    ]

    # PID 1 capability set is evidence-derived: the non-root JVM holds an EMPTY effective set.
    caps = runtime["linux_capabilities"]
    assert caps["effective"] == []
    assert "CapEff=0000000000000000" in caps["description"]
    baseline = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    assert "CapEff:\t0000000000000000" in baseline

    # Embedded Maven catalogue (445 libs + the OpenSearch application row).
    components = runtime["software_components"]
    assert len(components) == 446
    libs = [c for c in components if c["component_type"] == "library"]
    assert len(libs) == 445
    assert all(c["provenance"] == "sbom" and c["package_manager"] == "maven" for c in libs)

    # Security-plugin internal users are an identity authority.
    authorities = runtime["identity_authorities"]
    assert len(authorities) == 1
    authority = authorities[0]
    assert authority["identity_authority_id"] == "opensearch-security-internal-users"
    subject_names = {s["name"] for s in authority["subjects"]}
    assert "admin" in subject_names
    assert len(authority["subjects"]) == 7

    env = {item["name"]: item for item in runtime["environment"]}
    assert env["OPENSEARCH_INITIAL_ADMIN_PASSWORD"]["value_classification"] == "secret_fixture"
    assert env["OPENSEARCH_INITIAL_ADMIN_PASSWORD"]["value"] == ADMIN_PW_FIXTURE


def test_techvault_sdl_encodes_shuffle_opensearch_datastore(legacy_scenario):
    ds = legacy_scenario["nodes"]["shuffle-opensearch"]["runtime"]["datastore_services"][0]
    assert ds["engine"] == "opensearch"
    assert ds["data_model"] == "search_index"
    assert ds["version"] == "2.14.0"
    assert ds["cluster"]["name"] == "docker-cluster"
    assert ds["transport_security"]["mode"] == "mutual_tls"

    assert len(ds["partitions"]) == INDEX_COUNT
    assert len(ds["mappings"]) == INDEX_COUNT
    partition_names = {p["name"] for p in ds["partitions"]}
    assert "workflow-000001" in partition_names
    wf = next(m for m in ds["mappings"] if m["name"] == "workflow-000001")
    assert wf["top_level_field_count"] > 0


def test_techvault_sdl_compiles_with_shuffle_opensearch_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.shuffle-opensearch"].spec["node"]
    runtime = node["runtime"]
    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    ds = runtime["datastore_services"][0]
    assert ds["engine"] == "opensearch"
    assert len(ds["mappings"]) == INDEX_COUNT


def test_parity_inventory_cites_shuffle_opensearch_inventory():
    import yaml

    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text(encoding="utf-8"))["rows"]}
    row = rows["scen.techvault.shuffle-opensearch-inventory"]
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "nodes.techvault.shuffle-opensearch" in row["aces_target"]
    assert "docs/aces/inventory/shuffle-opensearch/" in row["validation_evidence"]
    assert "tests/test_shuffle_opensearch_inventory.py" in row["validation_evidence"]
