"""Checks for the SCN-010 shuffle-backend completion-grade inventory bundle."""

import gzip
import hashlib
import json
import lzma
import os
import re
from pathlib import Path

import pytest
import yaml

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)
from tests.techvault_sdl import load_legacy_techvault_sdl

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SHUFFLE_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "shuffle-backend"
SHUFFLE_DOC_PATH = SHUFFLE_DIR / "README.md"
CAPTURE_SCRIPT_PATH = SHUFFLE_DIR / "capture-evidence.sh"
LEDGER_PATH = SHUFFLE_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = SHUFFLE_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d"
IMAGE_DIGEST = (
    "ghcr.io/shuffle/shuffle-backend@"
    "sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d"
)
RUNTIME_PACKAGE_COUNT = 21
TRIVY_FINDING_COUNT = 90
SOFTWARE_COMPONENT_COUNT = 157
FILESYSTEM_ENTRY_COUNT = 2293
FILESYSTEM_CHECKSUM_COUNT = 1309
FILESYSTEM_INVENTORY_COUNT = 16
LOCAL_IDENTITY_USER_COUNT = 17
LOCAL_IDENTITY_GROUP_COUNT = 35
SERVICE_LISTENER_COUNT = 3
LEDGER_FACT_COUNT = 23

SHUFFLE_ORG_ID = "08b070b1-0ffd-4990-8b0f-ae1596d6121c"
SHUFFLE_ADMIN_USER_ID = "c98f23e2-5fd4-4907-9bef-5cd8d46fc8ca"

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.shuffle-backend.json",
    "docker-buildx-imagetools.attestation-amd64.raw.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.shuffle-backend.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.shuffle-data.json",
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
    "participant-discovery.shuffle-orborus.txt",
    "runtime-baseline.txt",
    "shuffle-state.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
    "trivy-sbom.cyclonedx.json.gz",
    "trivy-version.txt",
    "trivy-vulnerabilities.json.gz",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}

SCENARIO_SECRET_VALUES = (
    "31a211c4-ea5c-4a49-b022-5e2434e758a7",
    "ShuffleAdmin2024!",
    "StrongPassword123!",
)

PLACEHOLDER_PATTERNS = (
    r"<REDACTED",
    r"<OMITTED",
    r"withheld",
    r"absent from committed evidence",
)


@pytest.fixture(scope="module")
def sdl():
    return load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))


@pytest.fixture(scope="module")
def node(sdl):
    return sdl["nodes"]["shuffle-backend"]


@pytest.fixture(scope="module")
def runtime(node):
    return node["runtime"]


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


def _yaml_file(path: Path):
    if path == TECHVAULT_SDL_PATH:
        return load_legacy_techvault_sdl(str(path))
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[^-\n][^\n]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _passwd_rows() -> list[str]:
    return [line for line in _runtime_baseline_section("users") if ":" in line]


def _group_rows() -> list[str]:
    return [line for line in _runtime_baseline_section("groups") if ":" in line]


def test_shuffle_inventory_note_declares_completion_scope_and_caveats():
    text = SHUFFLE_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #360",
        "aptl-shuffle-backend",
        "Alpine Linux 3.22.2",
        "completion",
        "non-destructive",
        "did not run `aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "No known ACES expressivity gap remains",
        "runtime.service_listeners",
        "platform_kind: soar",
        "shuffle-opensearch",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Shuffle inventory note missing scope markers: {missing}"
    # The doc may reference the prior #353 pass for context, but must not frame
    # itself as a methodology smoke test / proof pass.
    assert "completion artifact, not a smoke test" in text
    assert "methodology smoke pass until a clean-lab capture" not in text
    assert "it is not the final completion artifact" not in text


def test_shuffle_capture_script_pins_toolchain_and_protocol_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "shuffle-backend",
        "/api/v1/health",
        "_cat/indices",
        "evidence-sha256sums.txt",
        "filesystem-tree.txt.gz",
        "osquery-listening-ports.json",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_shuffle_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(SHUFFLE_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 360
    assert ledger["asset"]["proof_scope"] != "methodology-smoke-test"
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "captured"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert all(
        disposition in {"encoded", "encoded_with_caveat"}
        for disposition in dispositions.values()
    )
    assert dispositions["shuffle-backend.application.platform-state"] == "encoded"
    assert dispositions["shuffle-backend.application.local-authorization"] == "encoded"
    assert dispositions["shuffle-backend.relationship.opensearch"] == "encoded_with_caveat"


def test_shuffle_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(SHUFFLE_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_shuffle_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_shuffle_evidence_sha256_manifest_matches_files():
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


def test_shuffle_mapping_ledger_references_every_evidence_file():
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
        f"evidence/{path.name}"
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
    }
    missing = evidence_files - refs
    assert not missing, f"Ledger does not reference every evidence file: {sorted(missing)}"


def test_shuffle_evidence_commits_scenario_secret_values():
    evidence_text = "\n".join(_evidence_text(path) for path in EVIDENCE_DIR.iterdir())
    missing = [value for value in SCENARIO_SECRET_VALUES if value not in evidence_text]
    assert not missing, f"Scenario secret values missing from evidence: {missing}"


def test_shuffle_evidence_does_not_commit_placeholder_secret_values():
    forbidden = re.compile("|".join(PLACEHOLDER_PATTERNS), re.IGNORECASE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Placeholder secret markers remain in evidence: {offenders}"


def test_shuffle_sdl_commits_scenario_secret_values(node):
    text = yaml.safe_dump(node, sort_keys=True)
    missing = [value for value in SCENARIO_SECRET_VALUES if value not in text]
    assert not missing, f"Scenario secret values missing from the expanded SDL: {missing}"


def test_shuffle_runtime_evidence_counts_and_caveats():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert image["Config"]["WorkingDir"] == "/app"
    assert container["HostConfig"]["Memory"] == 1073741824
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    # No healthcheck is declared in Compose, so the State carries no Health block.
    assert "Health" not in container["State"]

    assert (
        len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines())
        == RUNTIME_PACKAGE_COUNT
    )
    findings = _json_file("trivy-vulnerability-list.json")
    assert len(findings) == TRIVY_FINDING_COUNT
    assert {finding["severity"] for finding in findings} == {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN",
    }
    counts = {
        row["severity"]: row["count"]
        for row in _json_file("trivy-vulnerability-counts.json")
    }
    assert counts == {
        "CRITICAL": 3,
        "HIGH": 36,
        "MEDIUM": 25,
        "LOW": 23,
        "UNKNOWN": 3,
    }

    fs_rows = _evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()
    assert len(fs_rows) == FILESYSTEM_ENTRY_COUNT
    assert (
        len(_evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz").splitlines())
        == FILESYSTEM_CHECKSUM_COUNT
    )

    assert len(_passwd_rows()) == LOCAL_IDENTITY_USER_COUNT
    assert len(_group_rows()) == LOCAL_IDENTITY_GROUP_COUNT


def test_shuffle_state_records_org_admin_and_platform_counts():
    text = (EVIDENCE_DIR / "shuffle-state.txt").read_text(encoding="utf-8")
    assert SHUFFLE_ORG_ID in text
    assert SHUFFLE_ADMIN_USER_ID in text
    assert '"cluster_name": "docker-cluster"' in text
    assert '"version": "2.14.0"' in text
    # workflowexecution index docs.count == 934; org file store == 933.
    assert "workflowexecution-000001" in text
    assert "934" in text
    assert "933" in text


def test_shuffle_orborus_participant_discovery_reaches_backend():
    orborus = (EVIDENCE_DIR / "participant-discovery.shuffle-orborus.txt").read_text(
        encoding="utf-8"
    )
    assert "172.20.0.20" in orborus
    assert "shuffle-backend" in orborus
    assert '"success":true' in orborus


def test_shuffle_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert syft_version["application"] == "syft"

    assert (EVIDENCE_DIR / "trivy-version.txt").read_text(encoding="utf-8").strip() == (
        "Version: 0.70.0"
    )


def test_techvault_sdl_encodes_shuffle_runtime_surfaces(node, runtime):
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Alpine Linux 3.22.2"

    services = {(s["port"], s["protocol"], s["name"]) for s in node["services"]}
    assert services == {(5001, "tcp", "shuffle-api")}

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert {v["severity"] for v in runtime["package_vulnerabilities"]} == {
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
    }
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_INVENTORY_COUNT

    listeners = {item["service_listener_id"] for item in runtime["service_listeners"]}
    assert len(runtime["service_listeners"]) == SERVICE_LISTENER_COUNT
    assert "shuffle-api-5001" in listeners

    assert "process" not in runtime
    assert runtime["processes"][0]["pid"] == 1
    assert runtime["processes"][0]["user"] == "root"
    assert runtime["processes"][0]["command"] == ["./shufflebackend"]
    assert runtime["processes"][0]["working_directory"] == "/app"

    controls = {item["control_interface_id"]: item for item in runtime["local_control_interfaces"]}
    assert controls["shuffle-backend-docker-socket"]["access"] == "read_write"
    assert controls["shuffle-backend-docker-socket"]["path"] == "/var/run/docker.sock"

    endpoint = runtime["network"]["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.20"
    assert runtime["network"]["published_ports"] == []

    # ACES #471 removed the secret-name value-omission rule: secret-named env
    # vars carry their real scenario value (the backend injects them to realize
    # the stack), classified secret_fixture, never blanked.
    secret_env = {
        item["name"]: item["value"]
        for item in runtime["environment"]
        if item["value_classification"] == "secret_fixture"
    }
    assert secret_env == {
        "SHUFFLE_DEFAULT_APIKEY": "31a211c4-ea5c-4a49-b022-5e2434e758a7",
        "SHUFFLE_DEFAULT_PASSWORD": "ShuffleAdmin2024!",
        "SHUFFLE_OPENSEARCH_PASSWORD": "StrongPassword123!",
    }


def test_techvault_sdl_encodes_shuffle_application_and_identity(runtime):
    app = runtime["applications"][0]
    assert app["application_id"] == "shuffle-backend-api"
    routes = {route["route_id"]: route for route in app["routes"]}
    assert routes["health-get"]["path"] == "/api/v1/health"
    assert routes["health-get"]["auth_required"] is False
    assert routes["workflows-get"]["auth_required"] is True
    assert {"workflows-get", "apps-get", "users-get"} <= set(routes)

    authority = runtime["identity_authorities"][0]
    assert authority["identity_authority_id"] == "shuffle-local-authorization"
    subjects = {subject["subject_id"]: subject for subject in authority["subjects"]}
    assert set(subjects) == {"org-default", "user-admin", "apikey-default-admin"}
    admin_attrs = {
        attr["name"]: attr["values"]
        for attr in subjects["user-admin"]["attributes"]
    }
    assert admin_attrs["shuffle_user_id"] == [SHUFFLE_ADMIN_USER_ID]
    assert admin_attrs["role"] == ["admin"]


def test_techvault_sdl_encodes_shuffle_soar_platform(runtime):
    platform = runtime["platform_applications"][0]
    assert platform["platform_application_id"] == "shuffle-soar"
    assert platform["platform_kind"] == "soar"
    assert platform["product"] == "Shuffle"

    org = platform["organizations"][0]
    assert org["name"] == "default"
    assert SHUFFLE_ORG_ID in org["description"]

    content = {
        item["content_object_id"]: item["attributes"]["row_count"]
        for item in platform["content_objects"]
    }
    assert content["shuffle-workflows"] == 0
    assert content["shuffle-apps"] == 8
    assert content["shuffle-app-catalog"] == 313
    assert content["shuffle-executions"] == 934
    assert content["shuffle-files"] == 933

    bindings = {b["binding_id"]: b for b in platform["upstream_bindings"]}
    assert bindings["shuffle-opensearch-index"]["target_node_ref"] == "shuffle-opensearch"


def test_techvault_sdl_encodes_shuffle_opensearch_relationship(sdl):
    relationship = sdl["relationships"]["shuffle-backend-connects-opensearch"]
    assert relationship["properties"]["auth_method"] == "password"
    assert relationship["properties"]["tls_verification"] == "disabled"
    assert relationship["properties"]["port"] == "9200"
    assert "shuffle-opensearch" in sdl["nodes"]


def test_techvault_sdl_compiles_with_shuffle_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments[
        "provision.node.techvault.shuffle-backend"
    ].spec["node"]
    runtime = node["runtime"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["service_listeners"]) == SERVICE_LISTENER_COUNT
    assert runtime["platform_applications"][0]["platform_kind"] == "soar"
    assert (
        runtime["identity_authorities"][0]["identity_authority_id"]
        == "shuffle-local-authorization"
    )


def test_parity_inventory_cites_shuffle_completion_inventory():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    scen = rows["scen.techvault.shuffle-backend-inventory"]
    compose = rows["compose.service.shuffle-backend"]
    assert scen["category"] == "aces_sdl"
    assert compose["category"] == "aces_sdl"
    assert "tests/test_shuffle_backend_inventory.py" in scen["validation_evidence"]
    assert "tests/test_shuffle_backend_inventory.py" in compose["validation_evidence"]
    assert "#360" in scen["notes"]
