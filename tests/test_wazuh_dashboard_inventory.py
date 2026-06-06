"""Checks for the SCN-010 Wazuh dashboard steady-state inventory bundle."""

from pathlib import Path
import gzip
import hashlib
import json
import lzma
import re
import subprocess

import pytest
import yaml

from tests.techvault_sdl import load_legacy_techvault_sdl

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WAZUH_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "wazuh.dashboard"
WAZUH_DOC_PATH = WAZUH_DIR / "README.md"
CAPTURE_SCRIPT_PATH = WAZUH_DIR / "capture-evidence.sh"
LEDGER_PATH = WAZUH_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = WAZUH_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:8f5b50fde67a0b1c4d2321aa26b12bbc5cef21269cf4f6225746f0b946458bd7"
IMAGE_DIGEST = (
    "wazuh/wazuh-dashboard@"
    "sha256:8f5b50fde67a0b1c4d2321aa26b12bbc5cef21269cf4f6225746f0b946458bd7"
)
RUNTIME_PACKAGE_COUNT = 1594
RAW_SYFT_COMPONENT_COUNT = 1968
TRIVY_SBOM_COMPONENT_COUNT = 1868
SOFTWARE_COMPONENT_COUNT = 80
TRIVY_FINDING_COUNT = 378
FILESYSTEM_ENTRY_COUNT = 91312
FILESYSTEM_CHECKSUM_COUNT = 78821
FILESYSTEM_INVENTORY_COUNT = 40
LOCAL_IDENTITY_USER_COUNT = 14
LOCAL_IDENTITY_GROUP_COUNT = 25
SERVICE_LISTENER_COUNT = 3
LEDGER_FACT_COUNT = 18
FILESYSTEM_TREE_PARTS = (
    "filesystem-tree.txt.gz.part-000",
    "filesystem-tree.txt.gz.part-001",
)
FILESYSTEM_CHECKSUM_PARTS = tuple(
    f"filesystem-checksums.txt.xz.part-{index:03d}" for index in range(6)
)

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.wazuh.dashboard.json",
    "dashboard-config-files.redacted.txt",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.wazuh-dashboard-config.json",
    "docker-volume.wazuh-dashboard-custom.json",
    "evidence-sha256sums.txt",
    *FILESYSTEM_CHECKSUM_PARTS,
    *FILESYSTEM_TREE_PARTS,
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
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
    "trivy-sbom.cyclonedx.json.gz",
    "trivy-version.txt",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
    "wazuh-dashboard-probe.json",
    "wazuh-dashboard-state.txt",
}

# Raw secret values and private-key material that must not be committed.
RAW_SECRET_PATTERNS = (
    r"SecretPassword",
    r"WazuhPass123!",
    r"BEGIN .*PRIVATE KEY",
    r"authorization: Bearer",
)


@pytest.fixture(scope="module")
def sdl():
    return load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))


@pytest.fixture(scope="module")
def node(sdl):
    return sdl["nodes"]["wazuh-dashboard"]


@pytest.fixture(scope="module")
def runtime(node):
    return node["runtime"]


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _yaml_file(path: Path):
    if path == TECHVAULT_SDL_PATH:
        return load_legacy_techvault_sdl(str(path))
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    if path.suffix == ".xz":
        with lzma.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8", errors="ignore")


def _chunked_evidence_text(base_name: str) -> str:
    chunks = sorted(EVIDENCE_DIR.glob(f"{base_name}.part-*"))
    assert chunks, f"Missing chunked evidence for {base_name}"
    data = b"".join(path.read_bytes() for path in chunks)
    if base_name.endswith(".gz"):
        return gzip.decompress(data).decode("utf-8", errors="ignore")
    if base_name.endswith(".xz"):
        return lzma.decompress(data).decode("utf-8", errors="ignore")
    raise AssertionError(f"Unsupported chunked evidence type: {base_name}")


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z0-9-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _redact_with_capture_script(text: str) -> str:
    script = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    match = re.search(r"redact_stream\(\) \{\n.*?\n\}", script, re.DOTALL)
    assert match, "capture script must define redact_stream"
    result = subprocess.run(
        ["bash", "-c", f"{match.group(0)}\nredact_stream"],
        input=text,
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout


def test_wazuh_dashboard_inventory_note_declares_scope_and_evidence():
    text = WAZUH_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #342",
        "aptl-wazuh-dashboard",
        "wazuh/wazuh-dashboard:4.12.0",
        "existing running lab",
        "did not run `aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "Amazon Linux 2023",
        "runtime.platform_applications",
        "analytics-dashboard platform state",
        "No known ACES expressivity gap remains",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Wazuh dashboard inventory note missing markers: {missing}"


def test_wazuh_dashboard_capture_script_pins_toolchain_and_redaction():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "wazuh-dashboard-state.txt",
        "wazuh-dashboard-probe.json",
        "filesystem-tree.txt.gz.part-",
        "filesystem-checksums.txt.xz.part-",
        "write_chunked_stream",
        "evidence-sha256sums.txt",
        "syft:location:",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_wazuh_dashboard_capture_stream_redaction_is_key_aware():
    secret_value = "dash-4279-credential-1836"
    public_value = "public-observation-2026"
    redacted = _redact_with_capture_script(
        "\n".join(
            [
                f"INDEXER_PASSWORD={secret_value}",
                f"dashboard_password: {secret_value}",
                f"api_key = {secret_value}",
                f"server.ssl.key: {secret_value}",
                f"<password>{secret_value}</password>",
                f"<api_key>{secret_value}</api_key>",
                f"Authorization: Bearer {secret_value}",
                f"regular_field: {public_value}",
            ]
        )
    )

    assert secret_value not in redacted
    assert public_value in redacted
    assert "<REDACTED" in redacted


def test_wazuh_dashboard_mapping_ledger_validates_without_gap_triage():
    result = validate_mapping_ledger(WAZUH_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 342
    assert ledger["asset"]["proof_scope"] == "steady-state-asset-spec"
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["wazuh-dashboard.runtime.filesystem-inventory"] == (
        "encoded_with_caveat"
    )
    assert dispositions["wazuh-dashboard.platform-application"] == "encoded"
    assert dispositions["wazuh-dashboard.capture.toolchain-baseline"] == (
        "encoded_with_caveat"
    )


def test_wazuh_dashboard_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(WAZUH_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_wazuh_dashboard_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"
    assert not (EVIDENCE_DIR / "filesystem-tree.txt.gz").exists()
    assert not (EVIDENCE_DIR / "filesystem-checksums.txt.xz").exists()
    large_files = {
        path.name: path.stat().st_size
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and path.stat().st_size > 500 * 1024
    }
    assert not large_files, f"Evidence files exceed the pre-commit size gate: {large_files}"


def test_wazuh_dashboard_evidence_sha256_manifest_matches_files():
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


def test_wazuh_dashboard_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(
        ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", [])
    )
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {
        f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()
    }
    missing = evidence_files - refs
    assert not missing, f"Ledger does not reference every evidence file: {sorted(missing)}"


def test_wazuh_dashboard_evidence_does_not_contain_raw_secret_material():
    patterns = [re.compile(pattern, re.IGNORECASE) for pattern in RAW_SECRET_PATTERNS]
    offenders = {}
    for path in EVIDENCE_DIR.iterdir():
        if not path.is_file():
            continue
        text = _evidence_text(path)
        leaked = [pattern.pattern for pattern in patterns if pattern.search(text)]
        if leaked:
            offenders[path.name] = leaked
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_wazuh_dashboard_sdl_does_not_commit_raw_secret_material():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.IGNORECASE)
    text = TECHVAULT_SDL_PATH.read_text(encoding="utf-8")
    text += (PROJECT_ROOT / "scenarios" / "techvault" / "nodes").joinpath(
        "wazuh-dashboard.sdl.yaml"
    ).read_text(encoding="utf-8")
    assert not forbidden.search(text), "Raw secret material leaked into the SDL"


def test_wazuh_dashboard_runtime_evidence_counts_and_caveats():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert "wazuh/wazuh-dashboard:4.12.0" in image["RepoTags"]
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert container["Name"] == "/aptl-wazuh-dashboard"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Config"]["Hostname"] == "wazuh.dashboard"
    assert container["HostConfig"]["Memory"] == 1073741824
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "always"

    os_packages = (EVIDENCE_DIR / "os-packages.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    fs_rows = _chunked_evidence_text("filesystem-tree.txt.gz").splitlines()
    checksum_rows = _chunked_evidence_text(
        "filesystem-checksums.txt.xz"
    ).splitlines()
    assert len(os_packages) == 108
    assert len(fs_rows) == FILESYSTEM_ENTRY_COUNT
    assert len(checksum_rows) == FILESYSTEM_CHECKSUM_COUNT
    assert len(_runtime_baseline_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_runtime_baseline_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT

    counts = {
        row["severity"]: row["count"]
        for row in _json_file("trivy-vulnerability-counts.json")
    }
    assert counts == {"CRITICAL": 10, "HIGH": 183, "LOW": 25, "MEDIUM": 160}

    state = (EVIDENCE_DIR / "wazuh-dashboard-state.txt").read_text(encoding="utf-8")
    assert '"version": "4.12.0"' in state
    assert '"revision": "03"' in state
    assert '"version": "2.19.1"' in state
    assert "wazuh-dashboard-key.pem" in state


def test_wazuh_dashboard_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")
    findings = _json_file("trivy-vulnerability-list.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert len(syft_sbom["components"]) == RAW_SYFT_COMPONENT_COUNT
    assert len(trivy_sbom["components"]) == TRIVY_SBOM_COMPONENT_COUNT
    assert len(findings) == TRIVY_FINDING_COUNT
    assert syft_version["application"] == "syft"
    assert (EVIDENCE_DIR / "trivy-version.txt").read_text(encoding="utf-8").strip() == (
        "Version: 0.70.0"
    )


def test_techvault_sdl_encodes_wazuh_dashboard_runtime_surfaces(node, runtime):
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Amazon Linux 2023.8.20250818"
    assert node["services"] == [
        {
            "port": 5601,
            "protocol": "tcp",
            "name": "wazuh-dashboard-ui",
            "description": (
                "Wazuh/OpenSearch Dashboards HTTPS UI; Docker publishes host TCP "
                "443 to container TCP 5601."
            ),
        }
    ]

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_INVENTORY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == 2
    assert runtime["health"]["status"] == "healthy"
    assert runtime["linux_capabilities"]["add"] == []
    assert runtime["linux_capabilities"]["drop"] == []

    endpoint = runtime["network"]["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.11"
    assert runtime["network"]["published_ports"] == [
        {
            "container_port": 5601,
            "protocol": "tcp",
            "host_ip": "0.0.0.0",
            "host_port": 443,
            "description": "Docker host-published port observed from inspect.",
        }
    ]

    listeners = {
        item["service_listener_id"]: item for item in runtime["service_listeners"]
    }
    assert len(listeners) == SERVICE_LISTENER_COUNT
    assert listeners["dashboard-https-5601"]["port"] == 5601
    assert listeners["dashboard-https-5601"]["published_port_refs"][0][
        "host_port"
    ] == 443

    secret_env = {
        item["name"]
        for item in runtime["environment"]
        if item["value_classification"] == "redacted"
    }
    assert secret_env == {"API_PASSWORD", "DASHBOARD_PASSWORD", "INDEXER_PASSWORD"}
    assert all(
        "value" not in item or item["value"] == ""
        for item in runtime["environment"]
        if item["value_classification"] == "redacted"
    )


def test_techvault_sdl_encodes_wazuh_dashboard_application_and_platform(runtime):
    app = runtime["applications"][0]
    assert app["application_id"] == "wazuh-dashboard-web"
    routes = {route["route_id"]: route for route in app["routes"]}
    assert routes["dashboard-root-get"]["path"] == "/"
    assert routes["dashboard-root-get"]["auth_required"] is False
    assert routes["dashboard-root-get"]["responses"][0]["status_code"] == 302
    assert routes["api-status-get"]["path"] == "/api/status"
    assert routes["api-status-get"]["auth_required"] is True
    assert routes["api-status-get"]["responses"][0]["status_code"] == 401

    platform = runtime["platform_applications"][0]
    assert platform["platform_application_id"] == "wazuh-dashboard-platform"
    assert platform["platform_kind"] == "analytics_dashboard"
    assert platform["version"] == "4.12.0 / 2.19.1"

    content = {item["content_object_id"]: item for item in platform["content_objects"]}
    assert set(content) == {
        "wazuh-dashboard-default-route",
        "wazuh-dashboard-index-pattern",
    }
    assert (
        content["wazuh-dashboard-default-route"]["attributes"]["default_route"]
        == "/app/wz-home"
    )

    bindings = {item["binding_id"]: item for item in platform["upstream_bindings"]}
    assert bindings["wazuh-dashboard-index-backend"]["role"] == "index_backend"
    assert bindings["wazuh-dashboard-index-backend"]["target_node_ref"] == (
        "techvault.wazuh-indexer"
    )
    assert bindings["wazuh-dashboard-manager-api"]["role"] == "backend_api"
    assert bindings["wazuh-dashboard-manager-api"]["target_node_ref"] == "wazuh-manager"


def test_techvault_sdl_compiles_with_wazuh_dashboard_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments[
        "provision.node.techvault.wazuh-dashboard"
    ].spec["node"]
    runtime = node["runtime"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_INVENTORY_COUNT
    assert runtime["platform_applications"][0]["platform_kind"] == "analytics_dashboard"


def test_parity_inventory_cites_wazuh_dashboard_inventory():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    row = rows["scen.techvault.wazuh-dashboard-inventory"]
    assert row["category"] == "aces_sdl"
    assert "runtime.platform_applications" in row["aces_target"]
    assert "docs/aces/inventory/wazuh.dashboard/" in row["validation_evidence"]
    assert "tests/test_wazuh_dashboard_inventory.py" in row["validation_evidence"]
    assert "#342" in row["notes"]
    assert row["blocking_followup"] == "n/a"
