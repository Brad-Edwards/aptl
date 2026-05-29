"""Checks for the SCN-010 Wazuh manager steady-state inventory bundle."""

from collections import Counter
from pathlib import Path
import gzip
import hashlib
import json
import re
import subprocess

import pytest
import yaml

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WAZUH_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "wazuh.manager"
WAZUH_DOC_PATH = WAZUH_DIR / "README.md"
CAPTURE_SCRIPT_PATH = WAZUH_DIR / "capture-evidence.sh"
LEDGER_PATH = WAZUH_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = WAZUH_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_DIGEST_RE = re.compile(
    r"^wazuh/wazuh-manager@sha256:[0-9a-f]{64}$"
)

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.wazuh.manager.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-dmz.json",
    "docker-network.aptl-internal.json",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.filebeat-etc.json",
    "docker-volume.filebeat-var.json",
    "docker-volume.wazuh-active-response.json",
    "docker-volume.wazuh-agentless.json",
    "docker-volume.wazuh-api-configuration.json",
    "docker-volume.wazuh-etc.json",
    "docker-volume.wazuh-integrations.json",
    "docker-volume.wazuh-logs.json",
    "docker-volume.wazuh-queue.json",
    "docker-volume.wazuh-var-multigroups.json",
    "docker-volume.wazuh-wodles.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
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
    "wazuh-api-probe.json",
    "wazuh-manager-state.txt",
}

RAW_SECRET_PATTERNS = (
    r"SecretPassword",
    r"WazuhPass123!",
    r"BEGIN .*PRIVATE KEY",
    r"<key>[^<]+</key>",
    r"authorization: Bearer",
)


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _yaml_file(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8", errors="ignore")


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


def test_wazuh_manager_inventory_note_declares_scope_and_evidence():
    text = WAZUH_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #340",
        "aptl-wazuh-manager",
        "wazuh/wazuh-manager:4.12.0",
        "existing running lab",
        "not as clean-lab rebuild proof",
        "Amazon Linux 2023",
        "runtime.security_monitoring_managers",
        "ACES #428",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "No known ACES expressivity gap remains",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Wazuh manager inventory note missing scope markers: {missing}"


def test_wazuh_manager_capture_script_pins_toolchain_and_redaction():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "wazuh-manager-state.txt",
        "wazuh-api-probe.json",
        "evidence-sha256sums.txt",
        "syft:location:",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_wazuh_manager_capture_stream_redaction_is_key_aware():
    secret_value = "zulu-4279-mica-1836"
    public_value = "public-observation-2026"
    redacted = _redact_with_capture_script(
        "\n".join(
            [
                f"PASSWORD={secret_value}",
                f"password: {secret_value}",
                f"api_key = {secret_value}",
                f"cluster_key: {secret_value}",
                f"indexer_key: {secret_value}",
                f"x-api-key: {secret_value}",
                f"ssl.key = {secret_value}",
                f"<password>{secret_value}</password>",
                f"<api_key>{secret_value}</api_key>",
                f"<api-key>{secret_value}</api-key>",
                f"<private-key>{secret_value}</private-key>",
                f"Authorization: Bearer {secret_value}",
                f"regular_field: {public_value}",
            ]
        )
    )

    assert secret_value not in redacted
    assert public_value in redacted
    assert "<REDACTED" in redacted


def test_wazuh_manager_mapping_ledger_validates_without_gap_triage():
    result = validate_mapping_ledger(WAZUH_DIR)
    assert result.ok, result.errors
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 340
    assert IMAGE_DIGEST_RE.match(ledger["provenance"]["image_digest"])
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["wazuh-manager.security-monitoring.manager-state"] == "encoded"
    assert dispositions["wazuh-manager.security-monitoring.content-sets"] == "encoded"
    assert dispositions["wazuh-manager.capture.toolchain-baseline"] == "encoded_with_caveat"
    assert len(ledger["facts"]) >= 18


def test_wazuh_manager_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(WAZUH_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_wazuh_manager_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_wazuh_manager_evidence_sha256_manifest_matches_files():
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


def test_wazuh_manager_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(
        ref["path"]
        for ref in ledger["provenance"]["attestation"].get("evidence", [])
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
    assert evidence_files <= refs


def test_wazuh_manager_evidence_does_not_contain_raw_secret_material():
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


def test_wazuh_manager_runtime_evidence_and_security_monitoring_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]
    findings = _json_file("trivy-vulnerability-list.json")
    state = (EVIDENCE_DIR / "wazuh-manager-state.txt").read_text(encoding="utf-8")

    assert "wazuh/wazuh-manager:4.12.0" in image["RepoTags"]
    assert any(IMAGE_DIGEST_RE.match(digest) for digest in image["RepoDigests"])
    assert container["Name"] == "/aptl-wazuh-manager"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Config"]["Hostname"] == "wazuh.manager"
    assert container["HostConfig"]["Memory"] == 1073741824

    os_packages = (EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()
    sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    filesystem_entries = (EVIDENCE_DIR / "filesystem-tree.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(os_packages) == 118
    assert len(sbom["components"]) == 322
    assert len(filesystem_entries) == 933
    assert len(findings) == 368

    assert 'WAZUH_VERSION="<REDACTED' not in state
    assert 'WAZUH_VERSION="v4.12.0"' in state
    assert "Available agents:" in state
    assert "Groups (1):" in state
    assert "default (7)" in state
    assert "aptl-webapp-agent" in state
    assert "--rules-count--\n173" in state
    assert "--decoders-count--\n123" in state


def test_techvault_sdl_encodes_wazuh_manager_security_monitoring_surface():
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    node = scenario.nodes["wazuh-manager"]
    runtime = node.runtime
    assert runtime is not None
    assert len(runtime.filesystem_inventory) == 1220
    assert len(runtime.local_identity.users) == len(_runtime_baseline_section("users"))
    assert len(runtime.local_identity.groups) == len(_runtime_baseline_section("groups"))
    assert len(runtime.processes) == 22
    assert runtime.health.status == "healthy"
    assert len(runtime.packages) == 322
    assert len(runtime.package_vulnerabilities) == 368

    manager = runtime.security_monitoring_managers[0]
    assert manager.manager_id == "techvault-wazuh-manager"
    assert manager.implementation == "wazuh"
    assert manager.manager_kind == "siem"
    assert manager.version == "v4.12.0"
    assert manager.revision == "rc1"
    assert len(manager.listeners) == 4
    assert len(manager.components) >= 15
    assert len(manager.agents) == 7
    assert len(manager.agent_groups) == 1
    assert len(manager.content_sets) >= 4

    listener_roles = {listener.listener_id: listener.role for listener in manager.listeners}
    assert listener_roles["agent-events-1514"] == "agent_event_ingestion"
    assert listener_roles["agent-enrollment-1515"] == "agent_enrollment"
    assert listener_roles["syslog-514"] == "syslog_ingestion"
    assert listener_roles["wazuh-api-55000"] == "api"

    agents = {agent.agent_id: agent for agent in manager.agents}
    assert agents["aptl-webapp-agent"].status == "available"
    assert agents["aptl-suricata-agent"].group_refs == ["default"]

    groups = {group.group_id: group for group in manager.agent_groups}
    assert len(groups["default"].member_refs) == 7

    content_sets = {content.content_id: content for content in manager.content_sets}
    assert content_sets["wazuh-rule-corpus"].file_count == 173
    assert content_sets["wazuh-decoder-corpus"].file_count == 123


def test_techvault_sdl_compiles_with_wazuh_security_monitoring_refs():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.wazuh-manager"].spec["node"]
    manager = node["runtime"]["security_monitoring_managers"][0]

    assert manager["manager_id"] == "techvault-wazuh-manager"
    assert manager["implementation"] == "wazuh"
    assert len(node["runtime"]["packages"]) == 322
    assert len(node["runtime"]["package_vulnerabilities"]) == 368
    assert len(manager["agents"]) == 7
    assert len(manager["agent_groups"][0]["member_refs"]) == 7
    assert Counter(component["status"] for component in manager["components"]) >= Counter({
        "running": 11,
        "stopped": 4,
    })


def test_parity_inventory_cites_wazuh_manager_inventory_and_aces_428():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    row = rows["scen.techvault.wazuh-manager-inventory"]
    assert row["category"] == "aces_sdl"
    assert "runtime.security_monitoring_managers" in row["aces_target"]
    assert "docs/aces/inventory/wazuh.manager/" in row["validation_evidence"]
    assert "tests/test_wazuh_manager_inventory.py" in row["validation_evidence"]
    assert "Brad-Edwards/aces#428" in row["validation_evidence"]
    assert row["blocking_followup"] == "n/a"
