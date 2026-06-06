"""Checks for the SCN-010 Wazuh indexer steady-state inventory bundle."""

from collections import Counter
from pathlib import Path
import gzip
import hashlib
import json
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
INDEXER_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "wazuh.indexer"
INDEXER_DOC_PATH = INDEXER_DIR / "README.md"
CAPTURE_SCRIPT_PATH = INDEXER_DIR / "capture-evidence.sh"
LEDGER_PATH = INDEXER_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = INDEXER_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_DIGEST_RE = re.compile(r"^wazuh/wazuh-indexer@sha256:[0-9a-f]{64}$")

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.wazuh.indexer.json",
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
    "docker-volume.wazuh-indexer-data.json",
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
    "wazuh-indexer-api-probe.json",
    "wazuh-indexer-state.txt",
    "wazuh-indexer-templates.json.gz",
    "wazuh-indexer-family-mappings.json.gz",
    "wazuh-indexer-index-mappings-census.json",
}

# These patterns must NEVER match committed evidence; the redaction stream and
# out-of-band omission are the only acceptable ways for committed evidence to
# record secret material's existence. Each pattern is matched against the whole
# evidence file as a single string (no re.MULTILINE), so anchors are avoided —
# every pattern here is a substring/inline match that can actually fire.
RAW_SECRET_PATTERNS = (
    r"BEGIN .*PRIVATE KEY",  # raw PEM private key bytes
    r"\$2[ay]\$\d{2}\$[./A-Za-z0-9]{53}",  # bcrypt internal-user hash
    r"authorization:\s*Bearer\s+[A-Za-z0-9._-]+",  # bearer token
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


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z0-9-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _indexer_state_section(name: str) -> str:
    text = (EVIDENCE_DIR / "wazuh-indexer-state.txt").read_text(encoding="utf-8")
    marker = f"--{name}--"
    _, rest = text.split(marker, maxsplit=1)
    if rest.startswith("\n"):
        rest = rest[1:]
    next_match = None
    for cand in re.finditer(r"(?<![\w-])--[a-z0-9][a-z0-9-]{0,40}--", rest):
        next_match = cand
        break
    if not next_match:
        return rest.strip()
    return rest[: next_match.start()].strip()


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


def test_wazuh_indexer_inventory_note_declares_scope_and_evidence():
    text = INDEXER_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #341",
        "aptl-wazuh-indexer",
        "wazuh/wazuh-indexer:4.12.0",
        "existing running lab",
        "not as clean-lab rebuild proof",
        "Amazon Linux 2023",
        "runtime.datastore_services",
        "engine=opensearch",
        "data_model=search_index",
        "runtime.identity_authorities",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        # The note must honestly disclose the blocked surfaces + their ACES
        # issues, and that the inventory issue stays open until ACES lands them.
        "Blocked surfaces (open ACES expressivity gaps)",
        "Brad-Edwards/aces#468",
        "Brad-Edwards/aces#469",
        "Brad-Edwards/aces#470",
        "stays open until these ACES surfaces land",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Wazuh indexer inventory note missing scope markers: {missing}"
    # The over-claim the original pass shipped must never come back.
    assert "No known ACES expressivity gap remains" not in text


def test_wazuh_indexer_capture_script_pins_toolchain_and_redaction():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "wazuh-indexer-state.txt",
        "wazuh-indexer-api-probe.json",
        "evidence-sha256sums.txt",
        "INDEXER_USERNAME",
        "INDEXER_PASSWORD",
        "REDACTED-INDEXER-INTERNAL-USER-HASH",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_wazuh_indexer_capture_stream_redaction_is_key_aware():
    secret_value = "zulu-4279-mica-1836"
    public_value = "public-observation-2026"
    bcrypt_hash = "$2y$12$" + "a" * 53
    redacted = _redact_with_capture_script(
        "\n".join(
            [
                f"PASSWORD={secret_value}",
                f"password: {secret_value}",
                f"api_key = {secret_value}",
                f"indexer_password: {secret_value}",
                f"x-api-key: {secret_value}",
                f"ssl.key = {secret_value}",
                f"<password>{secret_value}</password>",
                f"<api_key>{secret_value}</api_key>",
                f'hash: "{bcrypt_hash}"',
                f"Authorization: Bearer {secret_value}",
                f"regular_field: {public_value}",
            ]
        )
    )

    assert secret_value not in redacted
    assert bcrypt_hash not in redacted
    assert public_value in redacted
    assert "<REDACTED" in redacted
    assert "<REDACTED-INDEXER-INTERNAL-USER-HASH>" in redacted


def test_wazuh_indexer_mapping_ledger_validates_with_recorded_aces_gaps():
    result = validate_mapping_ledger(INDEXER_DIR)
    assert result.ok, result.errors
    # No untriaged rows, but the OpenSearch cardinality/size, structured
    # mapping, and node-provenance surfaces are honestly recorded as blocked
    # on filed ACES expressivity issues rather than forced into SDL prose.
    assert result.triage_count == 0
    assert result.blocked_count == 4
    assert set(result.gap_issues) == {
        "Brad-Edwards/aces #468",
        "Brad-Edwards/aces #469",
        "Brad-Edwards/aces #470",
    }

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 341
    assert IMAGE_DIGEST_RE.match(ledger["provenance"]["image_digest"])
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    # Encoded surfaces: cluster identity, partition geometry, internal users.
    assert dispositions["wazuh-indexer.datastore.cluster-identity"] == "encoded_with_caveat"
    assert dispositions["wazuh-indexer.datastore.partition-geometry"] == "encoded_with_caveat"
    assert dispositions["wazuh-indexer.identity.internal-users"] == "encoded"
    # Plugin names encoded, per-plugin version blocked → caveat.
    assert dispositions["wazuh-indexer.datastore.plugins"] == "encoded_with_caveat"
    # Blocked surfaces: cardinality/size/identity, structured mappings, node provenance.
    assert dispositions["wazuh-indexer.datastore.cluster-cardinality"] == "blocked_by_aces_gap"
    assert dispositions["wazuh-indexer.datastore.partition-cardinality"] == "blocked_by_aces_gap"
    assert dispositions["wazuh-indexer.datastore.index-mappings"] == "blocked_by_aces_gap"
    assert dispositions["wazuh-indexer.datastore.node-provenance"] == "blocked_by_aces_gap"
    assert len(ledger["facts"]) >= 30


def test_wazuh_indexer_gap_report_records_blocked_surfaces_with_linked_issues():
    report = gap_report(INDEXER_DIR)
    assert report["triage_needed"] == []
    gaps = report["gaps"]
    by_fact = {g["fact_id"]: g for g in gaps}
    expected = {
        "wazuh-indexer.datastore.cluster-cardinality": 468,
        "wazuh-indexer.datastore.partition-cardinality": 468,
        "wazuh-indexer.datastore.index-mappings": 469,
        "wazuh-indexer.datastore.node-provenance": 470,
    }
    assert set(by_fact) == set(expected), f"unexpected blocked-fact set: {sorted(by_fact)}"
    for fact_id, issue_number in expected.items():
        gap = by_fact[fact_id]
        assert gap["gap_issue"]["tracker"] == "Brad-Edwards/aces"
        assert gap["gap_issue"]["number"] == issue_number
        assert gap["gap_issue"]["url"].endswith(f"/issues/{issue_number}")
        assert gap["why_not_current_surfaces"]
    # The structured-mapping gap must point at the real captured evidence,
    # not at SDL prose.
    mapping_evidence = {e["path"] for e in by_fact["wazuh-indexer.datastore.index-mappings"]["evidence"]}
    assert "evidence/wazuh-indexer-index-mappings-census.json" in mapping_evidence
    assert "evidence/wazuh-indexer-templates.json.gz" in mapping_evidence


def test_wazuh_indexer_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_wazuh_indexer_evidence_sha256_manifest_matches_files():
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


def test_wazuh_indexer_mapping_ledger_references_every_evidence_file():
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


def test_wazuh_indexer_evidence_does_not_contain_raw_secret_material():
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


def test_wazuh_indexer_runtime_evidence_and_opensearch_counts():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]
    findings = _json_file("trivy-vulnerability-list.json")
    state = (EVIDENCE_DIR / "wazuh-indexer-state.txt").read_text(encoding="utf-8")

    assert any(IMAGE_DIGEST_RE.match(digest) for digest in image["RepoDigests"])
    assert container["Name"] == "/aptl-wazuh-indexer"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Config"]["Hostname"] == "wazuh.indexer"
    assert container["HostConfig"]["Memory"] == 2 * 1024**3

    os_packages = (EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()
    sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    filesystem_entries = (EVIDENCE_DIR / "filesystem-tree.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    # Floor checks - exact counts drift with each scanner DB / image rev but
    # the bundle must never silently shrink.
    assert len(os_packages) >= 100
    assert len(sbom["components"]) >= 800
    assert len(filesystem_entries) >= 700
    assert len(findings) >= 200

    health = json.loads(_indexer_state_section("cluster-health"))
    assert health["cluster_name"] == "opensearch"
    assert health["status"] == "green"
    assert health["number_of_nodes"] == 1

    stats = json.loads(_indexer_state_section("cluster-stats-summary"))
    assert stats["cluster_name"] == "opensearch"
    assert stats["cluster_uuid"]
    assert stats["indices"]["count"] >= 30
    assert stats["nodes"]["versions"] == ["2.19.1"]

    cat_indices = json.loads(_indexer_state_section("cat-indices"))
    index_names = {row["index"] for row in cat_indices}
    assert any(name.startswith("wazuh-alerts-4.x-") for name in index_names)
    assert any(name.startswith("wazuh-archives-4.x-") for name in index_names)
    assert ".opendistro_security" in index_names

    plugins = json.loads(_indexer_state_section("cat-plugins"))
    plugin_components = {row["component"] for row in plugins}
    expected_plugins = {
        "opensearch-alerting",
        "opensearch-security",
        "opensearch-security-analytics",
        "opensearch-performance-analyzer",
        "opensearch-ml",
        "opensearch-sql",
    }
    assert expected_plugins <= plugin_components
    assert len(plugin_components) >= 18

    # Internal users YAML carries the six built-in users with redacted hashes.
    internal_users_yml = _indexer_state_section("internal-users-yml")
    assert "<REDACTED-INDEXER-INTERNAL-USER-HASH>" in internal_users_yml
    parsed_users = yaml.safe_load(internal_users_yml) or {}
    user_names = {k for k in parsed_users.keys() if k != "_meta"}
    assert user_names == {"admin", "kibanaserver", "kibanaro", "logstash", "readall", "snapshotrestore"}

    # opensearch.yml carries the discovery / port / TLS posture.
    opensearch_yml = _indexer_state_section("opensearch-yml")
    assert "discovery.type: single-node" in opensearch_yml
    assert "http.port: 9200-9299" in opensearch_yml
    assert "transport.tcp.port: 9300-9399" in opensearch_yml
    assert "network.host:" in opensearch_yml

    counts = _json_file("trivy-vulnerability-counts.json")
    severities = Counter({row["severity"]: row["count"] for row in counts})
    # Every observed severity bucket is in the closed-world enum.
    assert set(severities) <= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    assert sum(severities.values()) == len(findings)


def test_techvault_sdl_encodes_wazuh_indexer_datastore_surface():
    sdl = load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))
    nodes = sdl["nodes"]
    assert "wazuh-indexer" in nodes
    node = nodes["wazuh-indexer"]
    assert node["type"] == "vm"
    assert node["os"] == "linux"
    assert node["os_version"].startswith("Amazon Linux 2023")
    assert node["resources"]["ram"] == 2 * 1024**3

    runtime = node["runtime"]
    assert len(runtime["filesystem_inventory"]) >= 700
    assert len(runtime["packages"]) >= 800
    assert len(runtime["package_vulnerabilities"]) >= 200

    datastores = runtime["datastore_services"]
    assert len(datastores) == 1
    ds = datastores[0]
    assert ds["datastore_service_id"] == "techvault-wazuh-indexer"
    assert ds["engine"] == "opensearch"
    assert ds["data_model"] == "search_index"
    assert ds["cluster"]["name"] == "opensearch"
    assert ds["cluster"]["health"] == "green"
    assert ds["cluster"]["discovery_mode"] == "single-node"
    assert len(ds["nodes"]) == 1
    node_member = ds["nodes"][0]
    assert "cluster_manager" in node_member["roles"]
    assert "data" in node_member["roles"]
    assert "ingest" in node_member["roles"]
    partition_names = {p["name"] for p in ds["partitions"]}
    assert any(name.startswith("wazuh-alerts-4.x-") for name in partition_names)
    assert any(name.startswith("wazuh-archives-4.x-") for name in partition_names)
    assert ".opendistro_security" in partition_names
    setting_names = {s["name"] for s in ds["settings"]}
    assert {"discovery.type", "network.host", "http.port", "transport.tcp.port"} <= setting_names
    assert ds["transport_security"]["mode"] == "mutual_tls"
    assert ds["transport_security"]["client_verification"] is True
    # Plugin + template NAMES have a typed home and are encoded.
    assert len(ds["engine_plugins"]) >= 18
    template_names = set(ds.get("templates", []))
    assert {"wazuh", "wazuh-agent", "wazuh-statistics"} <= template_names

    # Honesty guard (the bug this re-encode fixes): blocked structured
    # observables must NOT be forced back into SDL prose. The datastore
    # service must carry zero per-index/cluster cardinality-size values and
    # zero engine build provenance in any description string; those live in
    # evidence + the blocked_by_aces_gap ledger facts.
    ds_blob = json.dumps(ds)
    forbidden_prose = [
        "u-vGl1n0Q7e",            # cluster uuid
        "docs.count",             # per-index doc count label
        "store.size",             # per-index store size label
        "store bytes",
        "dae2bfc93896",           # node build hash
        "1053842",                # aggregate doc count
        "1391460626",             # aggregate store bytes
    ]
    leaked = [needle for needle in forbidden_prose if needle in ds_blob]
    assert not leaked, f"blocked structured values leaked back into SDL prose: {leaked}"
    # The descriptions must instead reference the ACES blocker issues.
    assert "Brad-Edwards/aces#468" in ds_blob
    assert "Brad-Edwards/aces#469" in ds_blob
    assert "Brad-Edwards/aces#470" in ds_blob

    authorities = runtime["identity_authorities"]
    assert len(authorities) == 1
    authority = authorities[0]
    assert authority["identity_authority_id"] == "techvault-wazuh-indexer-opensearch-security"
    subject_names = {s["name"] for s in authority["subjects"]}
    assert {"admin", "kibanaserver", "kibanaro", "logstash", "readall", "snapshotrestore"} <= subject_names
    # Bcrypt hashes are redacted at capture; SDL never carries the raw hash.
    flattened = json.dumps(authority)
    assert "$2y$" not in flattened and "$2a$" not in flattened
    # The basic_internal_auth_domain authc service must be present.
    service_ids = {s["service_id"] for s in authority["services"]}
    assert "authc-basic-internal-auth-domain" in service_ids

    listeners = {ln["service_listener_id"]: ln for ln in runtime["service_listeners"]}
    assert listeners["opensearch-rest-9200"]["port"] == 9200
    assert listeners["opensearch-rest-9200"]["protocol"] == "tcp"
    assert listeners["opensearch-transport-9300"]["port"] == 9300

    endpoints = {e["network"]: e for e in runtime["network"]["endpoints"]}
    assert "security-net" in endpoints
    assert endpoints["security-net"]["ip_address"] == "172.20.0.12"
    published = {p["container_port"]: p for p in runtime["network"]["published_ports"]}
    assert published[9200]["host_port"] == 9200
    assert published[9200]["protocol"] == "tcp"


def test_techvault_sdl_compiles_with_wazuh_indexer_datastore_service():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.techvault.wazuh-indexer"].spec["node"]
    datastore = node["runtime"]["datastore_services"][0]
    assert datastore["engine"] == "opensearch"
    assert datastore["data_model"] == "search_index"
    assert len(datastore["partitions"]) >= 30
    assert datastore["cluster"]["health"] == "green"


def test_infrastructure_section_attaches_wazuh_indexer_to_security_net():
    sdl = load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))
    infra = sdl["infrastructure"]
    assert "wazuh-indexer" in infra
    indexer = infra["wazuh-indexer"]
    assert indexer["count"] == 1
    assert indexer["links"] == ["security-net"]
    flat_props = {}
    for entry in indexer["properties"]:
        flat_props.update(entry)
    assert flat_props["security-net"] == "172.20.0.12"


def test_parity_inventory_cites_wazuh_indexer_inventory():
    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text())["rows"]}
    row = rows["defconf.wazuh_indexer"]
    assert row["category"] == "aces_sdl"
    assert "runtime.datastore_services" in row["aces_target"]
    assert "docs/aces/inventory/wazuh.indexer/" in row["validation_evidence"]
    assert "tests/test_wazuh_indexer_inventory.py" in row["validation_evidence"]
