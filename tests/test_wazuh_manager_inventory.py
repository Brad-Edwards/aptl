"""Checks for the SCN-010 Wazuh manager steady-state inventory bundle."""

import gzip
import hashlib
import json
import os
import re
from collections import Counter
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
WAZUH_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "wazuh.manager"
WAZUH_DOC_PATH = WAZUH_DIR / "README.md"
CAPTURE_SCRIPT_PATH = WAZUH_DIR / "capture-evidence.sh"
LEDGER_PATH = WAZUH_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = WAZUH_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_DIGEST_RE = re.compile(r"^wazuh/wazuh-manager@sha256:[0-9a-f]{64}$")

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
    "wazuh-detection-definitions.decoders.json.gz",
    "wazuh-detection-definitions.rules.json.gz",
    "wazuh-detection-definitions.summary.json",
    "wazuh-manager-state.txt",
}

FORBIDDEN_CAPTURE_PLACEHOLDERS = (
    r"<REDACTED",
    r"<OMITTED",
    r"HTTP-[A-Z-]+-OMITTED",
    r"value withheld",
    r"absent from committed evidence",
)
FORBIDDEN_CAPTURE_HELPERS = (
    "redact_stream",
    "redact_env_jq",
    "redact_sensitive_keys",
    "sanitize_http_stream",
)


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
    return path.read_text(encoding="utf-8", errors="ignore")


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z0-9-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _wazuh_state_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "wazuh-manager-state.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z0-9-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _detection_definition_manifest() -> tuple[dict, list[dict]]:
    summary = _json_file("wazuh-detection-definitions.summary.json")
    rule_manifest = _json_file("wazuh-detection-definitions.rules.json.gz")
    decoder_manifest = _json_file("wazuh-detection-definitions.decoders.json.gz")
    return summary, rule_manifest["definitions"] + decoder_manifest["definitions"]


def _manifest_corpus_digest(definitions: list[dict]) -> str:
    lines = [
        f"{definition['definition_id']} {definition['canonical_digest']}"
        for definition in definitions
    ]
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


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


def test_wazuh_manager_capture_script_pins_toolchain_and_preserves_raw_capture():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "wazuh-manager-state.txt",
        "wazuh-api-probe.json",
        "wazuh-detection-definitions",
        "evidence-sha256sums.txt",
        "syft:location:",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert "redact_stream" not in text
    assert "<REDACTED" not in text
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_wazuh_manager_evidence_preserves_secret_shaped_scenario_values():
    container = json.dumps(_json_file("docker-inspect.container.json"))
    state = (EVIDENCE_DIR / "wazuh-manager-state.txt").read_text(encoding="utf-8")
    api_probe = _json_file("wazuh-api-probe.json")["output"]

    assert "INDEXER_PASSWORD=SecretPassword" in container
    assert "API_PASSWORD=WazuhPass123!" in container
    assert "password: 'SecretPassword'" in state
    assert "<key>/etc/ssl/filebeat.key</key>" in state
    assert 'WAZUH_VERSION="v4.12.0"' in state
    assert "HTTP/1.1 401 Unauthorized" in api_probe
    assert "No authorization token provided" in api_probe
    assert "<REDACTED" not in container
    assert "<REDACTED" not in state
    assert "<REDACTED" not in api_probe


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
    assert (
        dispositions["wazuh-manager.security-monitoring.detection-definitions"]
        == "encoded"
    )
    assert (
        dispositions["wazuh-manager.capture.toolchain-baseline"]
        == "encoded_with_caveat"
    )
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
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and path.name != "evidence-sha256sums.txt"
    }
    assert evidence_files <= manifest_entries


def test_wazuh_manager_mapping_ledger_references_every_evidence_file():
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
    assert evidence_files <= refs


def test_wazuh_manager_evidence_has_no_capture_placeholders_or_helpers():
    patterns = [
        re.compile(pattern, re.IGNORECASE) for pattern in FORBIDDEN_CAPTURE_PLACEHOLDERS
    ]
    offenders = {}
    for path in EVIDENCE_DIR.iterdir():
        if not path.is_file():
            continue
        text = _evidence_text(path)
        matches = [pattern.pattern for pattern in patterns if pattern.search(text)]
        matches.extend(helper for helper in FORBIDDEN_CAPTURE_HELPERS if helper in text)
        if matches:
            offenders[path.name] = matches
    assert not offenders, f"Evidence contains capture placeholders/helpers: {offenders}"


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

    os_packages = (
        (EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()
    )
    sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    filesystem_entries = (
        (EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines()
    )
    assert len(os_packages) == 118
    assert len(sbom["components"]) == 322
    assert len(filesystem_entries) == 933
    assert len(findings) == 368

    assert 'WAZUH_VERSION="v4.12.0"' in state
    assert "Available agents:" in state
    assert "Groups (1):" in state
    assert "default (7)" in state
    assert "aptl-webapp-agent" in state
    assert "--rules-count--\n173" in state
    assert "--decoders-count--\n123" in state


def test_wazuh_manager_detection_definition_manifest_is_complete():
    summary, definitions = _detection_definition_manifest()
    definition_ids = [definition["definition_id"] for definition in definitions]
    by_native_id = {definition["native_id"]: definition for definition in definitions}

    assert summary["definition_count"] == 6121
    assert summary["rule_definition_count"] == 4542
    assert summary["decoder_definition_count"] == 1579
    assert summary["parse_error_count"] == 0
    assert summary["unresolved_reference_count"] == 0
    assert len(definitions) == summary["definition_count"]
    assert len(definition_ids) == len(set(definition_ids))
    assert summary["corpus_digest"] == _manifest_corpus_digest(definitions)

    rule_files = _wazuh_state_section("rules-files")
    decoder_files = _wazuh_state_section("decoders-files")
    manifest_rule_files = {
        definition["source_file_ref"]
        for definition in definitions
        if definition["definition_kind"] != "decoder"
    }
    manifest_decoder_files = {
        definition["source_file_ref"]
        for definition in definitions
        if definition["definition_kind"] == "decoder"
    }
    assert set(rule_files) == manifest_rule_files
    assert set(decoder_files) == manifest_decoder_files

    tgs_rule = by_native_id["301010"]
    assert tgs_rule["definition_id"] == "wazuh-rule-301010"
    assert tgs_rule["match_strings"] == ["TGS-REQ"]
    assert tgs_rule["groups"] == ["ad", "kerberos"]

    correlation_rule = by_native_id["301011"]
    assert correlation_rule["definition_kind"] == "correlation_rule"
    assert correlation_rule["if_matched_sid_refs"] == ["wazuh-rule-301010"]
    assert correlation_rule["frequency"] == 5
    assert correlation_rule["timeframe_seconds"] == 60
    assert "kerberoasting" in correlation_rule["groups"]


def test_techvault_sdl_encodes_wazuh_manager_security_monitoring_surface():
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    node = scenario.nodes["techvault.wazuh-manager"]
    runtime = node.runtime
    assert runtime is not None
    assert len(runtime.filesystem_inventory) == 1220
    assert len(runtime.local_identity.users) == len(_runtime_baseline_section("users"))
    assert len(runtime.local_identity.groups) == len(
        _runtime_baseline_section("groups")
    )
    assert len(runtime.processes) == 22
    assert runtime.health.status == "healthy"
    assert len(runtime.packages) == 322
    assert len(runtime.package_vulnerabilities) == 368

    manager = runtime.security_monitoring_managers[0]
    assert manager.security_monitoring_manager_id == "techvault-wazuh-manager", (
        "ACES PR #458 renamed manager_id -> security_monitoring_manager_id under "
        "the <noun>_id primary-id convention."
    )
    assert manager.implementation == "wazuh"
    assert manager.manager_kind == "siem"
    assert manager.version == "v4.12.0"
    assert manager.revision == "rc1"
    assert len(manager.listeners) == 4
    assert len(manager.components) >= 15
    assert len(manager.agents) == 7
    assert len(manager.agent_groups) == 1
    assert len(manager.content_sets) >= 4
    assert len(manager.detection_definitions) == 6121

    listener_roles = {
        listener.listener_id: listener.role for listener in manager.listeners
    }
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

    _, manifest_definitions = _detection_definition_manifest()
    manifest_by_id = {
        definition["definition_id"]: definition for definition in manifest_definitions
    }
    sdl_by_id = {
        definition.definition_id: definition
        for definition in manager.detection_definitions
    }
    assert set(sdl_by_id) == set(manifest_by_id)
    for definition_id, expected in manifest_by_id.items():
        actual = sdl_by_id[definition_id]
        assert actual.native_id == expected["native_id"]
        assert actual.definition_kind == expected["definition_kind"]
        assert actual.content_set_ref == expected["content_set_ref"]
        assert actual.source_file_ref == expected["source_file_ref"]
        assert actual.canonical_digest == expected["canonical_digest"]


def test_techvault_sdl_compiles_with_wazuh_security_monitoring_refs():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.techvault.wazuh-manager"].spec["node"]
    manager = node["runtime"]["security_monitoring_managers"][0]

    assert manager["security_monitoring_manager_id"] == "techvault-wazuh-manager", (
        "ACES PR #458 renamed manager_id -> security_monitoring_manager_id under "
        "the <noun>_id primary-id convention."
    )
    assert manager["implementation"] == "wazuh"
    assert len(node["runtime"]["packages"]) == 322
    assert len(node["runtime"]["package_vulnerabilities"]) == 368
    assert len(manager["agents"]) == 7
    assert len(manager["agent_groups"][0]["member_refs"]) == 7
    assert Counter(
        component["status"] for component in manager["components"]
    ) >= Counter(
        {
            "running": 11,
            "stopped": 4,
        }
    )


def test_parity_inventory_cites_wazuh_manager_inventory_and_aces_428():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    row = rows["scen.techvault.wazuh-manager-inventory"]
    assert row["category"] == "aces_sdl"
    assert "runtime.security_monitoring_managers" in row["aces_target"]
    assert "docs/aces/inventory/wazuh.manager/" in row["validation_evidence"]
    assert "tests/test_wazuh_manager_inventory.py" in row["validation_evidence"]
    assert "Brad-Edwards/aces#428" in row["validation_evidence"]
    assert row["blocking_followup"] == "n/a"
