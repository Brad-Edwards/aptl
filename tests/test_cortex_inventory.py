"""Checks for the SCN-010 cortex steady-state inventory bundle."""

from pathlib import Path
import gzip
import hashlib
import json
import lzma
import re

import pytest

from tests.techvault_sdl import load_legacy_techvault_sdl
from aptl.core.aces_inventory import gap_report, load_mapping_ledger, validate_mapping_ledger

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "cortex"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"

IMAGE_ID = "sha256:ae8b3d72eb5de785513bc33492d93278c32b79d9ff89401463c3a9c577e0bc0b"
IMAGE_DIGEST = "thehiveproject/cortex@sha256:ae8b3d72eb5de785513bc33492d93278c32b79d9ff89401463c3a9c577e0bc0b"
RUNTIME_PACKAGE_COUNT = 213
TRIVY_FINDING_COUNT = 1060
FILESYSTEM_TREE_ROW_COUNT = 176
LOCAL_IDENTITY_USER_COUNT = 24
LOCAL_IDENTITY_GROUP_COUNT = 44
RUNTIME_PROCESS_COUNT = 4
RUNTIME_ENV_COUNT = 3
LEDGER_FACT_COUNT = 15

REQUIRED_EVIDENCE_FILES = {'cortex-state.txt', 'docker-buildx-imagetools.image.raw.json', 'compose-service.cortex-index-init.json', 'source-checksums.txt', 'thehive-cortex-auth-current-user.json', 'language-manifests.txt', 'compose-service.cortex.json', 'docker-buildx-imagetools.image.txt', 'filesystem-tree.txt.gz', 'trivy-version.txt', 'capture-limits.txt', 'os-packages.txt', 'cortex-index-documents.redacted.json', 'docker-inspect.image.json', 'participant-discovery.kali.txt', 'trivy-vulnerabilities.json.xz', 'osquery-installed-applications.json', 'osquery-docker-images.json', 'runtime-baseline.txt', 'docker-volume.cortex_data.json', 'osquery-listening-ports.json', 'docker-version.json', 'trivy-vulnerability-list.json', 'captured-at-utc.txt', 'filesystem-checksums.txt.xz', 'docker-compose-version.json', 'docker-inspect.container.json', 'trivy-sbom.cyclonedx.json.gz', 'syft-version.json', 'docker-logs.cortex.txt', 'trivy-vulnerability-counts.json', 'osquery-processes.json', 'syft-sbom.cyclonedx.json.gz', 'docker-history.image.txt', 'osquery-programs.json', 'docker-top.txt', 'osquery-version.txt', 'docker-history.image.jsonl', 'evidence-sha256sums.txt', 'docker-network.aptl-security.json', 'osquery-docker-containers.json', 'osquery-apt-sources.json'}
RAW_SECRET_PATTERNS = (
    r"aptlcortexlabapikey2026purple",
    r"AptlCortexService2026",
    r"BEGIN .*PRIVATE KEY",
    r"-----BEGIN OPENSSH",
)

@pytest.fixture(scope="module")
def legacy_scenario():
    return load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))


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


def test_cortex_note_declares_scope_and_integration():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = ("SCN-010", "issue #357", "aptl-cortex", IMAGE_DIGEST, "clean lab", "TheHive", "keyword", "No known ACES expressivity gap remains", "nodes.techvault.cortex")
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"cortex inventory note missing scope markers: {missing}"


def test_cortex_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = ("aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e", "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6", "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd", "cortex-state.txt", "thehive-cortex-auth-current-user.json", "evidence-sha256sums.txt")
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_cortex_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []
    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 357
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST


def test_cortex_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_cortex_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_cortex_evidence_sha256_manifest_matches_files():
    manifest = EVIDENCE_DIR / "evidence-sha256sums.txt"
    offenders = {}
    manifest_entries = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative_path = line.split("  ", maxsplit=1)
        manifest_entries.add(relative_path)
        path = ASSET_DIR / relative_path
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            offenders[relative_path] = {"expected": expected, "actual": actual}
    assert not offenders, f"Evidence checksum mismatches: {offenders}"
    evidence_files = {str(path.relative_to(ASSET_DIR)) for path in EVIDENCE_DIR.iterdir() if path.is_file() and path.name != "evidence-sha256sums.txt"}
    assert evidence_files <= manifest_entries


def test_cortex_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])
    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_cortex_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [path.name for path in EVIDENCE_DIR.iterdir() if path.is_file() and forbidden.search(_evidence_text(path))]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_cortex_runtime_evidence_counts_and_mapping():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]
    assert image["Id"] == IMAGE_ID
    assert image["RepoDigests"][0] == IMAGE_DIGEST
    assert container["HostConfig"]["Memory"] == 536870912
    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    current_user = _json_file("thehive-cortex-auth-current-user.json")
    assert current_user["id"] == "aptl-svc@cortex.local"
    assert current_user["organization"] == "APTL"
    assert current_user["roles"] == ["read", "analyze", "orgadmin"]
    state = (EVIDENCE_DIR / "cortex-state.txt").read_text(encoding="utf-8")
    assert '"relations":{"type":"keyword"}' in state
    assert '"status":{"type":"keyword"}' in state
    assert '"key":{"type":"keyword"}' in state


def test_techvault_sdl_encodes_cortex_runtime_and_relationships(legacy_scenario):
    node = legacy_scenario["nodes"]["cortex"]
    runtime = node["runtime"]
    assert node["source"]["version"] == IMAGE_DIGEST
    assert runtime["network"]["endpoints"][0]["ip_address"] == "172.20.0.22"
    assert any(listener["port"] == 9001 for listener in runtime["service_listeners"])
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_TREE_ROW_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    apps = {app["application_id"]: app for app in runtime["applications"]}
    assert apps["cortex-api"]["protocol"] == "http"
    auth = runtime["app_authorizations"][0]
    assert auth["principals"][0]["name"] == "aptl-svc@cortex.local"
    assert auth["principals"][0]["credential_classification"] == "redacted"
    relationships = legacy_scenario["relationships"]
    assert relationships["cortex-connects-thehive-es"]["target"] == "thehive-es"
    assert relationships["thehive-connects-cortex"]["target"] == "cortex"
