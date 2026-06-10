"""Checks for the SCN-010 shuffle-orborus steady-state inventory bundle."""

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
ASSET_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "shuffle-orborus"
DOC_PATH = ASSET_DIR / "README.md"
CAPTURE_SCRIPT_PATH = ASSET_DIR / "capture-evidence.sh"
LEDGER_PATH = ASSET_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = ASSET_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:e74e0246ba3acd0daaa8343e58da859f7908f06b9f51094a9cd9f9ea8cbf7a44"
IMAGE_DIGEST = "ghcr.io/shuffle/shuffle-orborus@sha256:e74e0246ba3acd0daaa8343e58da859f7908f06b9f51094a9cd9f9ea8cbf7a44"
RUNTIME_PACKAGE_COUNT = 21
TRIVY_FINDING_COUNT = 96
FILESYSTEM_TREE_ROW_COUNT = 3
SDL_FILESYSTEM_ENTRY_COUNT = 3
LOCAL_IDENTITY_USER_COUNT = 17
LOCAL_IDENTITY_GROUP_COUNT = 35
DOCKER_HISTORY_ROW_COUNT = 6
RUNTIME_PROCESS_COUNT = 2
RUNTIME_ENV_COUNT = 14
SOFTWARE_COMPONENT_COUNT = 139
LEDGER_FACT_COUNT = 18

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.shuffle-orborus.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.shuffle-orborus.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "language-manifests.txt",
    "orborus-state.txt",
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
}

RAW_SECRET_PATTERNS = (
    r"BEGIN .*PRIVATE KEY",
    r"-----BEGIN OPENSSH",
)


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


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def legacy_scenario():
    return load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))


@pytest.fixture(scope="module")
def compiled_runtime_model():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    return compile_runtime_model(parse_sdl_file(TECHVAULT_SDL_PATH))


def test_shuffle_orborus_note_declares_scope_and_realization_caveats():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #355",
        "aptl-shuffle-orborus",
        IMAGE_ID,
        "non-destructive",
        "did not run\n`aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "No known ACES expressivity gap remains",
        "nodes.techvault.shuffle-orborus",
        "orborus-polls-backend",
        "docker.sock",
        "host-root-equivalent",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"shuffle-orborus inventory note missing scope markers: {missing}"


def test_shuffle_orborus_capture_script_pins_toolchain_and_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "orborus-state.txt",
        "filesystem-tree.txt",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_shuffle_orborus_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(ASSET_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 355
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["shuffle-orborus.docker.socket"] == "encoded"
    assert dispositions["shuffle-orborus.relationship.backend"] == "encoded"
    assert dispositions["shuffle-orborus.runtime.service-listeners"] == "encoded_with_caveat"


def test_shuffle_orborus_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(ASSET_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_shuffle_orborus_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_shuffle_orborus_evidence_sha256_manifest_matches_files():
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


def test_shuffle_orborus_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_shuffle_orborus_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_shuffle_orborus_runtime_evidence_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["RepoDigests"][0] == IMAGE_DIGEST
    assert container["Config"]["Cmd"] == ["./orborus"]

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len((EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines()) == FILESYSTEM_TREE_ROW_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT


def test_shuffle_orborus_trivy_counts_match_severity_breakdown():
    counts = {row["severity"]: row["count"] for row in _json_file("trivy-vulnerability-counts.json")}
    assert counts == {"CRITICAL": 3, "HIGH": 36, "MEDIUM": 32, "LOW": 25}
    assert sum(counts.values()) == TRIVY_FINDING_COUNT


def test_shuffle_orborus_has_no_inbound_application_listener():
    # The only sockets are the backend-generated Docker embedded-DNS resolver on 127.0.0.11.
    rows = _json_file("osquery-listening-ports.json")["rows"]
    non_dns = [r for r in rows if r["address"] and not r["address"].startswith("127.0.0.11")]
    assert non_dns == [], f"orborus must expose no inbound listener; found: {non_dns}"


def test_shuffle_orborus_polls_backend_over_5001():
    state = (EVIDENCE_DIR / "orborus-state.txt").read_text(encoding="utf-8")
    assert "BASE_URL=http://shuffle-backend:5001" in state
    assert "shuffle-backend (172.20.0.20:5001) open" in state


def test_shuffle_orborus_docker_socket_is_writable_host_control_surface():
    state = (EVIDENCE_DIR / "orborus-state.txt").read_text(encoding="utf-8")
    container = _json_file("docker-inspect.container.json")[0]
    sock = [m for m in container["Mounts"] if m["Destination"] == "/var/run/docker.sock"]
    assert sock, "docker.sock bind mount missing from container inspect"
    assert sock[0]["Type"] == "bind"
    assert sock[0]["RW"] is True
    assert "docker.sock" in state


def test_techvault_sdl_encodes_shuffle_orborus_node(legacy_scenario):
    node = legacy_scenario["nodes"]["shuffle-orborus"]
    runtime = node["runtime"]

    assert node["source"]["name"] == "ghcr.io/shuffle/shuffle-orborus"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Alpine Linux v3.22"

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == SDL_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT

    network = runtime["network"]
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.6"
    assert network["published_ports"] == []

    proc_names = {p["name"] for p in runtime["processes"]}
    assert {"orborus", "timeout"} == proc_names
    orborus_proc = next(p for p in runtime["processes"] if p["name"] == "orborus")
    assert orborus_proc["role"] == "primary"
    assert orborus_proc["command"] == ["./orborus"]


def test_techvault_sdl_encodes_shuffle_orborus_docker_control_surface(legacy_scenario):
    runtime = legacy_scenario["nodes"]["shuffle-orborus"]["runtime"]

    interfaces = runtime["local_control_interfaces"]
    assert len(interfaces) == 1
    iface = interfaces[0]
    assert iface["control_interface_id"] == "shuffle-orborus-docker-socket"
    assert iface["kind"] == "unix_socket"
    assert iface["access"] == "read_write"
    assert iface["path"] == "/var/run/docker.sock"

    sock_mounts = [m for m in runtime["mounts"] if "docker.sock" in m["target"]]
    assert len(sock_mounts) == 1
    assert sock_mounts[0]["source_kind"] == "bind"
    assert sock_mounts[0]["read_only"] is False

    # The only listeners are the backend-generated Docker embedded-DNS loopback sockets.
    listeners = runtime["service_listeners"]
    assert {l["scope"] for l in listeners} == {"loopback_only"}
    assert {l["address"] for l in listeners} == {"127.0.0.11"}


def test_techvault_sdl_encodes_orborus_backend_relationship(legacy_scenario):
    rel = legacy_scenario["relationships"]["orborus-polls-backend"]
    assert rel["source"] == "shuffle-orborus"
    assert rel["target"] == "shuffle-backend"
    assert rel["properties"]["base_url"] == "http://shuffle-backend:5001"
    assert rel["properties"]["port"] == "5001"


def test_techvault_sdl_compiles_with_shuffle_orborus_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.shuffle-orborus"].spec["node"]
    runtime = node["runtime"]
    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert len(runtime["local_control_interfaces"]) == 1
    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["network"]["published_ports"] == []


def test_parity_inventory_cites_shuffle_orborus_inventory():
    import yaml

    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text(encoding="utf-8"))["rows"]}
    row = rows["scen.techvault.shuffle-orborus-inventory"]
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "nodes.techvault.shuffle-orborus" in row["aces_target"]
    assert "docs/aces/inventory/shuffle-orborus/" in row["validation_evidence"]
    assert "tests/test_shuffle_orborus_inventory.py" in row["validation_evidence"]
