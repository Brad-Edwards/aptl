"""Checks for APTL's downstream ACES inventory ledger proof pass."""

from collections import Counter
from pathlib import Path
import hashlib
import json
import re

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app
from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    mapping_ledger_schema,
    validate_mapping_ledger,
)


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
METHODOLOGY_PATH = (
    PROJECT_ROOT / "docs" / "aces" / "inventory" / "asset-inventory-methodology.md"
)
ASSURANCE_REPORT_PATH = (
    PROJECT_ROOT / "docs" / "aces" / "inventory" / "methodology-assurance-report.md"
)
SHUFFLE_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "shuffle-backend"
SHUFFLE_DOC_PATH = SHUFFLE_DIR / "README.md"
LEDGER_PATH = SHUFFLE_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = SHUFFLE_DIR / "evidence"
ACES_INVENTORY_DOC_URL = (
    "https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/"
    "asset-inventory-methodology.md"
)
ACES_ASSURANCE_REPORT_URL = (
    "https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/"
    "methodology-assurance-report.md"
)
ACES_CAPTURE_SKILL_URL = (
    "https://github.com/Brad-Edwards/aces/tree/dev/.codex-skills/"
    "aces-asset-inventory-capture"
)

IMAGE_DIGEST = (
    "ghcr.io/shuffle/shuffle-backend@"
    "sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d"
)
IMAGE_ID = "sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d"
SECRET_ENV_NAMES = (
    "SHUFFLE_DEFAULT_APIKEY",
    "SHUFFLE_DEFAULT_PASSWORD",
    "SHUFFLE_OPENSEARCH_PASSWORD",
)
REQUIRED_EVIDENCE_FILES = {
    "captured-at-utc.txt",
    "compose-service.shuffle-backend.json",
    "docker-buildx-imagetools.attestation-amd64.raw.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-inspect.trivy-image.json",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.shuffle-data.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "language-manifests.txt",
    "os-packages.txt",
    "runtime-baseline.txt",
    "trivy-sbom.cyclonedx.json",
    "trivy-version.txt",
    "trivy-vulnerabilities.json",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}


def _json_file(name: str):
    with (EVIDENCE_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def test_methodology_doc_rehomes_authority_to_aces():
    text = METHODOLOGY_PATH.read_text(encoding="utf-8")
    required = (
        "APTL no longer owns or republishes",
        "The canonical methodology now lives in ACES",
        ACES_INVENTORY_DOC_URL,
        ACES_ASSURANCE_REPORT_URL,
        ACES_CAPTURE_SKILL_URL,
        "APTL remains a downstream implementation and validation target",
        "TechVault evidence bundles",
        "mapping-ledger.yaml",
        "current reference ledger CLI",
        "aptl aces-inventory validate",
        "aptl aces-inventory gaps",
        "aptl aces-inventory schema",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Methodology redirect missing expected anchors: {missing}"
    forbidden = (
        "APTL-local methodology spike",
        "APTL is the reference reality",
        "Capture and Specification Recipe",
        "Issue Breakdown Implication",
    )
    offenders = [needle for needle in forbidden if needle in text]
    assert not offenders, f"APTL still carries methodology authority: {offenders}"


def test_shuffle_backend_note_declares_proof_scope():
    text = SHUFFLE_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "methodology smoke test",
        "not the final completion artifact",
        "already-running local lab",
        "Docker socket bind",
        "If a participant or agent can discover a fact from inside the range",
        "ACES specification mapping must be attempted",
        "not the semantic frame for the ACES SDL gap",
        "Facts that ACES cannot express become ACES issues",
        "ACES #354",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "aptl aces-inventory gaps",
        "aptl aces-inventory schema",
        "in-toto layer with SLSA provenance",
        "APTL #330",
        "APTL #331",
        "APTL #332",
        "APTL #353",
        "ACES docs as the canonical methodology owner",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Shuffle inventory note missing scope markers: {missing}"
    assert "No ACES SDL encoding or gap issues were filed" not in text


def test_methodology_assurance_report_rehomes_authority_to_aces():
    text = ASSURANCE_REPORT_PATH.read_text(encoding="utf-8")
    required = (
        "APTL no longer owns or republishes",
        "canonical ACES report",
        ACES_ASSURANCE_REPORT_URL,
        "APTL-specific assurance claims",
        "per-asset evidence bundles",
        "ledger records",
        "aptl aces-inventory",
        "downstream reference tooling",
        "methodology and assurance rationale are ACES-owned",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Assurance report redirect missing anchors: {missing}"
    assert "NIST SP 800-128" not in text
    assert "This report reviews the APTL #353" not in text


def test_mapping_ledger_validates_and_tracks_gap_handoff():
    result = validate_mapping_ledger(SHUFFLE_DIR)
    assert result.ok, result.errors
    assert result.fact_count == 9
    assert result.encoded_count == 9
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []
    assert result.warnings == ["supply-chain attestations captured but not verified"]

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["provenance"]["attestation"]["status"] == "captured"
    assert ledger["provenance"]["attestation"]["verification_status"] == "not_verified"
    assert ledger["provenance"]["attestation"]["predicate_types"] == [
        "https://slsa.dev/provenance/v0.2"
    ]
    assert len(ledger["correspondence_checks"]) == 2
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["shuffle-backend.image.identity"] == "encoded"
    assert dispositions["shuffle-backend.network.identity"] == "encoded"
    assert dispositions["shuffle-backend.docker.socket"] == "encoded"
    assert set(dispositions.values()) == {"encoded"}
    assert all(fact["evidence"] for fact in ledger["facts"])


def test_gap_report_has_no_remaining_shuffle_backend_aces_gaps():
    report = gap_report(SHUFFLE_DIR)
    assert report["gaps"] == []
    assert not report["triage_needed"]


def test_mapping_ledger_schema_is_formalized_for_iteration():
    schema = mapping_ledger_schema()
    assert schema["title"] == "MappingLedger"
    properties = schema["properties"]
    assert "provenance" in properties
    assert "correspondence_checks" in properties
    assert "facts" in properties


def test_aces_inventory_cli_validates_and_lists_gaps():
    runner = CliRunner()

    validate_result = runner.invoke(
        app, ["aces-inventory", "validate", str(SHUFFLE_DIR)]
    )
    assert validate_result.exit_code == 0
    assert "Inventory ledger OK" in validate_result.stdout
    assert "facts=9 encoded=9 blocked=0 triage=0" in validate_result.stdout
    assert "warning: supply-chain attestations captured but not verified" in (
        validate_result.stdout
    )

    gaps_result = runner.invoke(app, ["aces-inventory", "gaps", str(SHUFFLE_DIR)])
    assert gaps_result.exit_code == 0
    assert "Inventory gaps for shuffle-backend" in gaps_result.stdout
    assert "blocked=0 triage=0" in gaps_result.stdout
    assert "ACES #354" not in gaps_result.stdout

    schema_result = runner.invoke(app, ["aces-inventory", "schema"])
    assert schema_result.exit_code == 0
    assert '"title": "MappingLedger"' in schema_result.stdout
    assert '"correspondence_checks"' in schema_result.stdout


def test_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_evidence_sha256_manifest_matches_files():
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


def test_buildx_attestation_evidence_captures_slsa_provenance_manifest():
    image_index = _json_file("docker-buildx-imagetools.image.raw.json")
    attestation = _json_file("docker-buildx-imagetools.attestation-amd64.raw.json")
    assert image_index["mediaType"] == "application/vnd.oci.image.index.v1+json"
    assert any(
        manifest.get("annotations", {}).get("vnd.docker.reference.type")
        == "attestation-manifest"
        for manifest in image_index["manifests"]
    )
    layer = attestation["layers"][0]
    assert layer["mediaType"] == "application/vnd.in-toto+json"
    assert (
        layer["annotations"]["in-toto.io/predicate-type"]
        == "https://slsa.dev/provenance/v0.2"
    )


def test_image_identity_is_digest_pinned():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["WorkingDir"] == "/app"
    assert image["Config"]["Cmd"] == ["./shufflebackend"]
    assert "5001/tcp" in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 8


def test_container_runtime_state_and_redaction_boundary():
    container = _json_file("docker-inspect.container.json")[0]
    env = container["Config"]["Env"]
    joined_env = "\n".join(env)

    assert container["Name"] == "/aptl-shuffle-backend"
    assert container["State"]["Running"] is True
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "shuffle-backend"
    assert container["Config"]["Image"] == "ghcr.io/shuffle/shuffle-backend:latest"
    assert container["HostConfig"]["Memory"] == 1073741824
    assert (
        "/var/run/docker.sock:/var/run/docker.sock:rw"
        in container["HostConfig"]["Binds"]
    )
    assert (
        container["NetworkSettings"]["Networks"]["aptl_aptl-security"]["IPAddress"]
        == "172.20.0.20"
    )

    for name in SECRET_ENV_NAMES:
        assert re.search(rf"^{name}=<REDACTED-[A-Z0-9-]+>$", joined_env, re.MULTILINE)
    assert "SHUFFLE_DEFAULT_PASSWORD=<REDACTED-SHUFFLE-DEFAULT-PASSWORD>" in env
    assert "SHUFFLE_OPENSEARCH_PASSWORD=<REDACTED-SHUFFLE-OPENSEARCH-PASSWORD>" in env


def test_evidence_bundle_does_not_contain_raw_secret_values():
    offenders = {}
    raw_secret_assignment = re.compile(
        rf"^({'|'.join(re.escape(name) for name in SECRET_ENV_NAMES)})=(?!<REDACTED-).+",
        re.MULTILINE,
    )
    for path in EVIDENCE_DIR.iterdir():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        leaked = sorted(
            match.group(1) for match in raw_secret_assignment.finditer(text)
        )
        if leaked:
            offenders[path.name] = leaked
    assert not offenders, f"Raw secret assignments leaked into evidence: {offenders}"


def test_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        "VERSION_ID=3.22.2",
        "uid=0(root)",
        "/app",
        ":::5001",
        "./shufflebackend",
        "/shuffle-database",
        "/run/docker.sock",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_trivy_sbom_is_cyclonedx_for_the_pinned_image():
    sbom = _json_file("trivy-sbom.cyclonedx.json")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert sbom["metadata"]["component"]["name"] == IMAGE_DIGEST

    tools = sbom["metadata"]["tools"]["components"]
    trivy_tools = [tool for tool in tools if tool.get("name") == "trivy"]
    assert trivy_tools
    assert trivy_tools[0]["version"] == "0.70.0"


def test_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)

    assert counts == dict(computed)
    assert counts == {"CRITICAL": 5, "HIGH": 33, "LOW": 7, "MEDIUM": 41}
    assert len(vulnerabilities) == 86


def test_compose_service_records_backend_surfaces():
    service = _json_file("compose-service.shuffle-backend.json")
    assert service["image"] == "ghcr.io/shuffle/shuffle-backend:latest"
    assert service["container_name"] == "aptl-shuffle-backend"
    assert service["hostname"] == "shuffle-backend"
    assert "soc" in service["profiles"]
    assert service["networks"]["aptl-security"]["ipv4_address"] == "172.20.0.20"
    assert "/var/run/docker.sock:/var/run/docker.sock" in service["volumes"]
    assert "shuffle_data:/shuffle-database" in service["volumes"]
