"""Checks for the SCN-010 TechVault composition inventory bundle."""

import hashlib
import json
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

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPOSITION_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "_composition"
DOC_PATH = COMPOSITION_DIR / "README.md"
CAPTURE_SCRIPT_PATH = COMPOSITION_DIR / "capture-evidence.sh"
LEDGER_PATH = COMPOSITION_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = COMPOSITION_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

LEDGER_FACT_COUNT = 11
COMPOSITION_CONTENT_ITEM_COUNT = 569
REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "composition-account-host-map.json",
    "composition-content-placement.json",
    "composition-dependency-graph.json",
    "composition-mount-sharing.json",
    "composition-network-topology.json",
    "composition-per-asset-index.json",
    "composition-relationship-index.json",
    "composition-sdl-surface-index.json",
    "evidence-sha256sums.txt",
}


def _json_file(name: str):
    with (EVIDENCE_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def test_composition_note_declares_scope_and_validation_contract():
    text = DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #329",
        "TechVault scenario composition",
        "runtime-composed",
        "docs/aces/inventory/_composition/",
        "No known ACES expressivity gap remains",
        "uv run aptl aces-inventory validate",
        "uv run aptl aces-inventory gaps",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"composition inventory note missing scope markers: {missing}"


def test_composition_capture_script_records_snapshot_evidence_without_secrets():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "composition-network-topology.json",
        "composition-per-asset-index.json",
        "composition-dependency-graph.json",
        "composition-mount-sharing.json",
        "evidence-sha256sums.txt",
        "capture-limits.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing composition evidence outputs: {missing}"
    assert "printenv" not in text
    assert "env >" not in text
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_composition_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(COMPOSITION_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 329
    assert ledger["asset"]["scenario"] == "TechVault"
    assert ledger["provenance"]["image_digest"].startswith("not-applicable:")
    assert ledger["provenance"]["attestation"]["status"] == "not_applicable"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["composition.network.topology"] == "encoded"
    assert dispositions["composition.defensive.workflow-chains"] == "encoded_with_caveat"


def test_composition_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(COMPOSITION_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_composition_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_composition_evidence_sha256_manifest_matches_files():
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


def test_composition_mapping_ledger_references_every_evidence_file():
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


def test_composition_evidence_does_not_commit_raw_secret_material():
    forbidden = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|APTL\{|^Token:|PASSWORD=|SECRET=|API_KEY=",
        re.MULTILINE,
    )
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
        and forbidden.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert not offenders, f"Generated secret material leaked into evidence: {offenders}"


def test_composition_network_topology_captures_cross_network_placement():
    topology = _json_file("composition-network-topology.json")
    networks = {item["id"]: item for item in topology["networks"]}
    assert networks["techvault.redteam-net"]["cidr"] == "172.20.4.0/24"
    assert networks["techvault.dmz-net"]["gateway"] == "172.20.1.1"
    assert networks["techvault.internal-net"]["cidr"] == "172.20.2.0/24"
    assert networks["techvault.security-net"]["cidr"] == "172.20.0.0/24"

    assignments = {
        (item["node"], item["network"]): item["address"]
        for item in topology["static_assignments"]
    }
    assert assignments[("techvault.webapp", "techvault.dmz-net")] == "172.20.1.20"
    assert assignments[("techvault.webapp", "techvault.internal-net")] == "172.20.2.25"
    assert assignments[("techvault.dns", "techvault.dmz-net")] == "172.20.1.22"
    assert assignments[("techvault.dns", "techvault.internal-net")] == "172.20.2.27"
    assert assignments[("techvault.dns", "techvault.security-net")] == "172.20.0.25"
    assert assignments[("techvault.kali", "techvault.redteam-net")] == "172.20.4.30"
    assert assignments[("techvault.kali", "techvault.dmz-net")] == "172.20.1.30"
    assert assignments[("techvault.kali", "techvault.internal-net")] == "172.20.2.35"


def test_composition_dependency_and_relationship_evidence_has_key_chains():
    graph = _json_file("composition-dependency-graph.json")
    dependency_edges = {
        (edge["source"], edge["target"])
        for edge in graph["edges"]
        if edge["kind"] in {"infrastructure_dependency", "compose_depends_on"}
    }
    assert ("techvault.webapp", "techvault.db") in dependency_edges
    assert ("techvault.misp", "techvault.misp-db") in dependency_edges
    assert ("techvault.misp", "techvault.misp-redis") in dependency_edges
    assert ("techvault.misp-suricata-sync", "techvault.misp") in dependency_edges
    assert ("techvault.wazuh-dashboard", "techvault.wazuh-manager") in dependency_edges

    relationship_edges = {
        (edge["source"], edge["target"])
        for edge in graph["edges"]
        if edge["kind"] == "relationship"
    }
    assert ("techvault.thehive", "techvault.cortex") in relationship_edges
    assert ("techvault.misp-suricata-sync", "techvault.suricata") in relationship_edges


def test_composition_mounts_content_and_accounts_are_indexed():
    mounts = _json_file("composition-mount-sharing.json")
    shared_volumes = {item["volume"]: item["services"] for item in mounts["shared_volumes"]}
    assert {"db_data", "suricata_logs", "suricata_command_socket"} <= set(shared_volumes)
    assert set(shared_volumes["db_data"]) == {"db", "wazuh-sidecar-db"}
    assert set(shared_volumes["suricata_logs"]) == {"suricata", "wazuh-sidecar-suricata"}
    assert set(shared_volumes["suricata_command_socket"]) == {
        "misp-suricata-sync",
        "suricata",
    }

    content = _json_file("composition-content-placement.json")
    assert content["item_count"] == COMPOSITION_CONTENT_ITEM_COUNT
    items = {item["id"]: item for item in content["items"]}
    suricata_config = items["suricata-file-etc-suricata-yaml"]
    assert suricata_config["targets"] == ["techvault.suricata"]
    assert suricata_config["path"] == "/etc/suricata/suricata.yaml"
    assert suricata_config["source_name"] == "config/suricata/suricata.yaml"

    accounts = _json_file("composition-account-host-map.json")
    assert "techvault.webapp" in accounts["accounts_by_node"]
    assert "techvault.kali" in accounts["accounts_by_node"]
    assert accounts["raw_secret_values_included"] is False


def test_techvault_sdl_does_not_define_synthetic_scenario_actors():
    with TECHVAULT_SDL_PATH.open(encoding="utf-8") as fh:
        root_sdl = yaml.safe_load(fh)

    assert "entities" not in root_sdl
    assert "agents" not in root_sdl
    assert root_sdl["forwarding_agents"]


def test_parity_inventory_points_at_composition_bundle_and_tests():
    with PARITY_PATH.open(encoding="utf-8") as fh:
        rows = {row["id"]: row for row in yaml.safe_load(fh)["rows"]}

    row = rows["scen.techvault.composition-inventory"]
    assert row["category"] == "aces_sdl"
    assert "docs/aces/inventory/_composition/" in row["validation_evidence"]
    assert "tests/test_techvault_composition_inventory.py" in row["validation_evidence"]
    assert "scenarios/techvault.sdl.yaml" in row["validation_evidence"]
    assert "No known remaining ACES expressivity blocker" in row["notes"]
