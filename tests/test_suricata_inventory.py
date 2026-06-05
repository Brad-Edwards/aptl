"""Checks for the SCN-010 suricata steady-state inventory bundle.

suricata is the first passive network-sensor archetype in TechVault: the ledger
carries two ``blocked_by_aces_gap`` facts (ACES #429 monitoring posture, #430
typed IDS/NDR family) alongside the cleanly-encoded runtime surfaces.
"""

from pathlib import Path
import gzip
import hashlib
import json
import re

import yaml

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SURICATA_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "suricata"
SURICATA_DOC_PATH = SURICATA_DIR / "README.md"
CAPTURE_SCRIPT_PATH = SURICATA_DIR / "capture-evidence.sh"
LEDGER_PATH = SURICATA_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = SURICATA_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

# Local image config ID (docker inspect .Id) — distinct from the upstream digest.
IMAGE_CONFIG_ID = "sha256:66cbeff9c0dbf4b42d4344374c9df1fc0c254023c8ec53ed3feb7ffe815f2d1d"
# Canonical upstream registry manifest-list digest for the jasonish/suricata:7.0
# tag (docker buildx imagetools inspect) — what source.version pins to.
IMAGE_DIGEST = "jasonish/suricata@sha256:7b3fa735ba2bc7c1e3e764e6070c0a319935a737ca86e86e86d2640e408295fe"
IMAGE_MANIFEST_LIST_DIGEST = "sha256:7b3fa735ba2bc7c1e3e764e6070c0a319935a737ca86e86e86d2640e408295fe"
RUNTIME_PACKAGE_COUNT = 191
TRIVY_FINDING_COUNT = 18
FILESYSTEM_ENTRY_COUNT = 29
LOCAL_IDENTITY_USER_COUNT = 18
LOCAL_IDENTITY_GROUP_COUNT = 36
LEDGER_FACT_COUNT = 20
LEDGER_ENCODED_COUNT = 20
LEDGER_BLOCKED_COUNT = 0
AUTHORED_CONTENT_FILES = 6
BUILD_HISTORY_LAYER_COUNT = 17
SOURCE_INPUT_COUNT = 6  # suricata.yaml, local.rules, + 4 MISP baselines
NODE_KEY = "techvault.suricata"
GAP_ISSUES = []  # ACES #429/#430 landed; both formerly-blocked facts are now encoded

REQUIRED_EVIDENCE_FILES = {'docker-logs.suricata.txt', 'docker-volume.suricata-logs.json', 'docker-network.aptl-dmz.json', 'osquery-version.txt', 'participant-discovery.kali.txt', 'docker-inspect.container.json', 'docker-buildx-imagetools.image.txt', 'docker-buildx-imagetools.image.raw.json', 'docker-history.image.jsonl', 'osquery-processes.json', 'suricata-state.txt', 'docker-network.aptl-internal.json', 'captured-at-utc.txt', 'osquery-programs.json', 'os-packages.txt', 'docker-history.image.txt', 'source-checksums.txt', 'docker-top.txt', 'osquery-docker-images.json', 'osquery-installed-applications.json', 'trivy-vulnerability-counts.json', 'osquery-docker-containers.json', 'docker-inspect.image.json', 'docker-network.aptl-security.json', 'osquery-listening-ports.json', 'osquery-apt-sources.json', 'syft-version.json', 'trivy-sbom.cyclonedx.json.gz', 'trivy-vulnerability-list.json', 'filesystem-tree.txt', 'capture-limits.txt', 'docker-volume.suricata-command-socket.json', 'trivy-version.txt', 'language-manifests.txt', 'syft-sbom.cyclonedx.json.gz', 'compose-service.suricata.json', 'docker-compose-version.json', 'filesystem-checksums.txt', 'evidence-sha256sums.txt', 'runtime-baseline.txt', 'docker-version.json'}

RAW_SECRET_PATTERNS = (
    r"BEGIN .*PRIVATE KEY",
    r"APTL\{",
)


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8", errors="ignore")


def _yaml_file(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_suricata_inventory_note_declares_scope_and_gap_caveats():
    text = SURICATA_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #345",
        "aptl-suricata",
        "jasonish/suricata:7.0",
        "AlmaLinux 9.7",
        "first passive network-sensor archetype",
        "no listening TCP/UDP service",
        "unix command socket",
        "Brad-Edwards/aces#429",
        "Brad-Edwards/aces#430",
        "runtime.network_sensors",
        "runtime.network_detection_engines",
        "content.suricata-*",
        "no `accounts` entries",
        "no remaining blocker",
        "not as clean-lab rebuild proof",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Suricata inventory note missing scope markers: {missing}"


def test_suricata_capture_script_pins_reproducible_toolchain_and_passive_probe():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "docker-history.image.jsonl",
        "participant-discovery.kali.txt",
        "suricata-state.txt",
        "not content-checksummed",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_suricata_mapping_ledger_validates_with_no_remaining_gaps():
    result = validate_mapping_ledger(SURICATA_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_ENCODED_COUNT
    assert result.blocked_count == LEDGER_BLOCKED_COUNT
    assert result.triage_count == 0
    assert result.gap_issues == GAP_ISSUES

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 345
    assert ledger["asset"]["source_class"] == "upstream-image-plus-mounted-config"
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["suricata.runtime.command-socket"] == "encoded"
    assert dispositions["suricata.content.authored-config"] == "encoded_with_caveat"
    # ACES #429/#430 landed — both formerly-blocked facts are now encoded (with caveat)
    assert dispositions["suricata.sensor.monitoring-posture"] == "encoded_with_caveat"
    assert dispositions["suricata.ids.detection-engine"] == "encoded_with_caveat"
    assert dispositions["suricata.capture.toolchain-baseline"] == "encoded_with_caveat"


def test_suricata_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(SURICATA_DIR)
    assert report["triage_needed"] == []
    assert report["gaps"] == []


def test_suricata_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_suricata_evidence_sha256_manifest_matches_files():
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


def test_suricata_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_suricata_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
        and path.name not in {"filesystem-checksums.txt", "evidence-sha256sums.txt"}
        and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_suricata_runtime_evidence_counts_and_passive_posture():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_CONFIG_ID
    # The canonical upstream digest is the registry manifest-list digest from
    # buildx imagetools — NOT the local config ID that docker mirrors into RepoDigests.
    buildx = (EVIDENCE_DIR / "docker-buildx-imagetools.image.txt").read_text(encoding="utf-8")
    assert IMAGE_MANIFEST_LIST_DIGEST in buildx

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len((EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines()) == FILESYSTEM_ENTRY_COUNT

    participant = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "22 (ssh) : Connection refused" in participant
    assert "passive IDS sensor" in participant

    state = (EVIDENCE_DIR / "suricata-state.txt").read_text(encoding="utf-8")
    assert "Suricata version 7.0.15" in state
    assert "suricata-command.socket" in state


def test_suricata_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_version["application"] == "syft"


def test_techvault_sdl_encodes_suricata_inventory_surfaces():
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    node = scenario.nodes[NODE_KEY]
    assert node.source.version == IMAGE_DIGEST
    assert node.os_version == "AlmaLinux 9.7 (Moss Jungle Cat)"
    # passive sensor: no node services and no published ports
    assert node.services == []

    runtime = node.runtime
    assert runtime is not None
    assert len(runtime.packages) == RUNTIME_PACKAGE_COUNT
    assert len(runtime.package_vulnerabilities) == TRIVY_FINDING_COUNT
    assert len(runtime.filesystem_inventory) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime.local_identity.users) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime.local_identity.groups) == LOCAL_IDENTITY_GROUP_COUNT
    assert runtime.network.published_ports == []
    assert {ep.network for ep in runtime.network.endpoints} == {
        "techvault.dmz-net", "techvault.internal-net", "techvault.security-net"}

    # the unix command socket is the only control surface
    assert len(runtime.local_control_interfaces) == 1
    socket = runtime.local_control_interfaces[0]
    assert socket.kind.value == "unix_socket"
    assert socket.path == "/var/run/suricata/suricata-command.socket"

    caps = runtime.linux_capabilities
    assert set(caps.add) == {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_NICE"}

    assert runtime.software_components[0].version == "7.0.15"

    # passive network sensor posture (ACES #429 surface)
    assert len(runtime.network_sensors) == 1
    sensor = runtime.network_sensors[0]
    assert sensor.implementation.value == "suricata"
    assert sensor.monitoring_posture.value == "passive"
    assert sensor.capture_mode.value == "pcap"
    assert sensor.network_sensor_id == "suricata-sensor"
    assert set(sensor.monitored_network_refs) == {
        "techvault.dmz-net", "techvault.internal-net", "techvault.security-net"}

    # IDS/NDR detection engine (ACES #430 surface)
    assert len(runtime.network_detection_engines) == 1
    engine = runtime.network_detection_engines[0]
    assert engine.implementation.value == "suricata"
    assert {p.value for p in engine.app_layer_protocols} == {"http", "tls", "dns", "ssh", "smtp", "ftp", "smb"}
    assert {rs.source_id for rs in engine.rule_sources} == {"suricata-rules", "local-rules", "misp-iocs"}
    assert {o.format.value for o in engine.output_streams} == {"eve_json", "fast_log"}
    assert engine.control_channels[0].kind.value == "unix_socket"
    assert "rule_reload" in [c.value for c in engine.control_channels[0].capabilities]

    # wazuh log-forwarding is now a typed forwarding_edge into the scenario-level
    # forwarding_agents registry (ACES #460), not a plain connects_to.
    relationship = scenario.relationships["techvault.suricata-logs-forwarded-wazuh"]
    assert relationship.source == "techvault.suricata"
    assert relationship.target == "techvault.wazuh-manager"
    assert relationship.forwarding_edge.forwarder_ref == "aptl-suricata-wazuh-agent"
    agent_ids = {fa.forwarding_agent_id for fa in scenario.forwarding_agents}
    assert "aptl-suricata-wazuh-agent" in agent_ids


def test_techvault_sdl_encodes_suricata_authored_content_and_no_accounts():
    """The six APTL-authored config/ruleset files are content entries placed on
    the node; the suricata user is image-provided so there are no authored accounts.
    """
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    content = {k: v for k, v in scenario.content.items() if "suricata-file" in k}
    assert len(content) == AUTHORED_CONTENT_FILES
    # every authored content file targets the suricata node, is a File, and cites a repo source + sha256
    for entry in content.values():
        assert entry.target == "techvault.suricata"
        assert entry.type.value == "file"
        assert entry.source.name.startswith("config/suricata/")
        assert entry.source.version.startswith("sha256:")
    # the two direct binds and the three verbatim MISP hash-list sidecars are present
    paths = {e.path for e in content.values()}
    assert "/etc/suricata/suricata.yaml" in paths
    assert "/etc/suricata/rules/local.rules" in paths
    assert "/var/lib/suricata/rules/misp/misp-sha256.list" in paths

    # no authored accounts on this node — the suricata user is image-provided
    assert [k for k in scenario.accounts if "suricata" in k] == []


def test_techvault_sdl_compiles_with_suricata_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.techvault.suricata"].spec["node"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(build["instructions"]) == BUILD_HISTORY_LAYER_COUNT
    assert len(build["layers"]) == BUILD_HISTORY_LAYER_COUNT
    # non-empty layers carry their real byte sizes (not all zeroed)
    assert any(layer["size"] > 0 for layer in build["layers"])
    assert all((layer["size"] == 0) == layer["empty"] for layer in build["layers"])
    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert build["attestation"]["status"] == "absent"
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["network"]["endpoints"]) == 3
    assert runtime["network"]["published_ports"] == []
    assert runtime["container"]["runtime_name"] == "runc"
    assert len(runtime["local_control_interfaces"]) == 1


def test_parity_inventory_cites_suricata_inventory_and_gaps():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}

    encoded = rows["scen.techvault.suricata-inventory"]
    assert encoded["category"] == "aces_sdl"
    assert "nodes.suricata" in encoded["aces_target"]
    assert "tests/test_suricata_inventory.py" in encoded["validation_evidence"]
    assert encoded["blocking_followup"] == "n/a"

    # ACES #429/#430 landed — both gap rows are now aces_sdl with no blocking followup
    posture = rows["scen.techvault.suricata-sensor-posture"]
    assert posture["category"] == "aces_sdl"
    assert posture["blocking_followup"] == "n/a"
    assert "runtime.network_sensors" in posture["aces_target"]

    engine = rows["scen.techvault.suricata-ids-engine"]
    assert engine["category"] == "aces_sdl"
    assert engine["blocking_followup"] == "n/a"
    assert "runtime.network_detection_engines" in engine["aces_target"]
