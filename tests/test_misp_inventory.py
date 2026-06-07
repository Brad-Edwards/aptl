"""Checks for the SCN-010 MISP steady-state inventory bundle."""

from pathlib import Path
import gzip
import hashlib
import json
import lzma
import re

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
MISP_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "misp"
MISP_DOC_PATH = MISP_DIR / "README.md"
CAPTURE_SCRIPT_PATH = MISP_DIR / "capture-evidence.sh"
LEDGER_PATH = MISP_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = MISP_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"
TECHVAULT_NAMESPACE = "techvault"
MISP_NODE_ID = f"{TECHVAULT_NAMESPACE}.misp"
MISP_CONTENT_ID = f"{TECHVAULT_NAMESPACE}.misp-reference-datasets"
MISP_REL_PREFIX = f"{TECHVAULT_NAMESPACE}."

IMAGE_ID = "sha256:992fd95b8d9698a18e1acdd7dbf5e8d03b32a03fd80e4bcbcff77bc7f17768cd"
IMAGE_DIGEST = (
    "ghcr.io/misp/misp-docker/misp-core@"
    "sha256:992fd95b8d9698a18e1acdd7dbf5e8d03b32a03fd80e4bcbcff77bc7f17768cd"
)
RUNTIME_PACKAGE_COUNT = 238
TRIVY_FINDING_COUNT = 593
FILESYSTEM_ENTRY_COUNT = 17516
FILESYSTEM_CHECKSUM_COUNT = 12544
LOCAL_IDENTITY_USER_COUNT = 21
LOCAL_IDENTITY_GROUP_COUNT = 42
DOCKER_HISTORY_ROW_COUNT = 33
IMAGE_LAYER_COUNT = 21
SOURCE_INPUT_COUNT = 4
RUNTIME_PROCESS_COUNT = 49
RUNTIME_ENV_COUNT = 18
SERVICE_LISTENER_COUNT = 15
PLATFORM_CONTENT_OBJECT_COUNT = 10
PLATFORM_SETTING_COUNT = 6
LEDGER_FACT_COUNT = 27

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.misp.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.misp.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.misp-config.json",
    "docker-volume.misp-data.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
    "language-manifests.txt",
    "misp-state.txt",
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
    "participant-discovery.misp-suricata-sync.txt",
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
    r"misp_db_password",
    r"misp_root_password",
    r"redispassword",
    r"BEGIN .*PRIVATE KEY",
    r"data\[_Token\]\[key\]",
    r"ADMIN_PASSWORD=admin",
    r"admin@admin\.test\s+admin\b",
    r"JHxB",
    r"V9Xw",
)


@pytest.fixture(scope="module")
def scenario():
    from aces_sdl import parse_sdl_file

    return parse_sdl_file(TECHVAULT_SDL_PATH)


@pytest.fixture(scope="module")
def compiled_runtime_model(scenario):
    from aces_processor.compiler import compile_runtime_model

    return compile_runtime_model(scenario)


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


def _filesystem_tree_rows() -> list[list[str]]:
    rows = []
    for line in _evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines():
        parts = line.split("\t")
        if len(parts) == 1:
            parts = line.split("\\t")
        rows.append(parts)
    return rows


def _misp_content_counts() -> dict[str, int]:
    lines = _runtime_state_section("db-content-counts")
    return {
        row.split("\t")[0]: int(row.split("\t")[1])
        for row in lines[1:]
        if "\t" in row
    }


def _misp_admin_settings() -> dict[str, str]:
    lines = _runtime_state_section("db-admin-settings")
    rows = {}
    for line in lines[1:]:
        parts = line.split("\t", maxsplit=2)
        if len(parts) == 3:
            rows[parts[1]] = parts[2]
    return rows


def _runtime_state_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "misp-state.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[^-\n][^\n]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _unique_osquery_listeners() -> set[tuple[str, str, str, str, str, str]]:
    rows = _json_file("osquery-listening-ports.json")["rows"]
    return {
        (
            row["address"],
            row["path"],
            row["pid"],
            row["port"],
            row["protocol"],
            row["socket"],
        )
        for row in rows
    }


def test_misp_inventory_note_declares_scope_and_realization_caveats():
    text = MISP_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #346",
        "aptl-misp",
        "MISP 2.5.36",
        "Debian GNU/Linux 13",
        "non-destructive",
        "did not run `aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "ACES #431 is consumed",
        "No known ACES expressivity gap remains",
        "runtime.service_listeners",
        "zero events",
        "#348 and #349",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"MISP inventory note missing scope markers: {missing}"


def test_misp_capture_script_pins_toolchain_and_protocol_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "yq -o=json '.services.misp'",
        "participant-discovery.misp-suricata-sync.txt",
        "/events/restSearch",
        "select id,setting,value from admin_settings",
        "evidence-sha256sums.txt",
        "filesystem-tree.txt.gz",
        "osquery-listening-ports.json",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_misp_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(MISP_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 346
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["misp.runtime.service-listeners"] == "encoded_with_caveat"
    assert dispositions["misp.application.local-authorization"] == "encoded"
    assert dispositions["misp.application.platform-settings"] == "encoded"
    assert dispositions["misp.application.content-state"] == "encoded_with_caveat"
    assert dispositions["misp.relationship.redis"] == "encoded_with_caveat"


def test_misp_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(MISP_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_misp_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_misp_evidence_sha256_manifest_matches_files():
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


def test_misp_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_misp_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_misp_runtime_evidence_counts_and_caveats():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["WorkingDir"] == "/var/www/MISP"
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["HostConfig"]["Memory"] == 2147483648

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_filesystem_tree_rows()) == FILESYSTEM_ENTRY_COUNT
    assert all(len(row) == 12 for row in _filesystem_tree_rows())
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz").splitlines()) == FILESYSTEM_CHECKSUM_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_json_file("trivy-vulnerabilities.json.gz")["Metadata"]["Layers"]) == IMAGE_LAYER_COUNT

    counts = _misp_content_counts()
    assert counts["events"] == 0
    assert counts["attributes"] == 0
    assert counts["objects"] == 0
    assert counts["taxonomies"] == 165
    assert counts["galaxies"] == 112
    assert counts["galaxy_clusters"] == 49300
    assert counts["warninglists"] == 122
    assert counts["sharing_groups"] == 0
    assert counts["object_templates"] == 388

    settings = _misp_admin_settings()
    assert settings["db_version"] == "146"
    assert settings["fix_login"] == "2026-05-23 06:19:07"
    assert settings["default_role"] == "3"
    assert settings["clean_db"] == "0"
    assert "addIPLogging" in settings["update_progress"]
    assert settings["update_fail_number"] == "0"

    assert len(_runtime_baseline_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_runtime_baseline_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(_runtime_baseline_section("environment")) == RUNTIME_ENV_COUNT
    assert len(_json_file("osquery-processes.json")["rows"]) == RUNTIME_PROCESS_COUNT
    assert len(_unique_osquery_listeners()) == SERVICE_LISTENER_COUNT


def test_misp_participant_discovery_records_expected_reachability():
    sync = (EVIDENCE_DIR / "participant-discovery.misp-suricata-sync.txt").read_text(encoding="utf-8")
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "172.20.0.16     misp" in sync
    assert "misp:443 reachable" in sync
    assert "misp:80 reachable" in sync
    assert "Verification: OK" in sync
    assert "TLSv1.3" in sync
    assert "Network is unreachable" in kali


def test_misp_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert syft_version["application"] == "syft"


def test_techvault_sdl_encodes_misp_inventory_surfaces(scenario):
    node = scenario.nodes[MISP_NODE_ID]
    assert node.source.version == IMAGE_DIGEST
    assert node.os_version == "Debian GNU/Linux 13 (trixie)"
    assert len(node.source.build.instructions) == DOCKER_HISTORY_ROW_COUNT
    assert len(node.source.build.layers) == IMAGE_LAYER_COUNT
    assert len(node.source.build.source_inputs) == SOURCE_INPUT_COUNT
    assert node.source.build.attestation.status == "absent"

    services = {service.name: service.port for service in node.services}
    assert services == {"http": 80, "https": 443, "misp-zmq": 50000, "supervisor-http": 9001}

    runtime = node.runtime
    assert runtime is not None
    assert len(runtime.packages) == RUNTIME_PACKAGE_COUNT
    assert len(runtime.package_vulnerabilities) == TRIVY_FINDING_COUNT
    assert len(runtime.filesystem_inventory) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime.local_identity.users) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime.local_identity.groups) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime.processes) == RUNTIME_PROCESS_COUNT
    assert len(runtime.environment) == RUNTIME_ENV_COUNT
    assert len(runtime.service_listeners) == SERVICE_LISTENER_COUNT

    env = {item.name: item for item in runtime.environment}
    assert env["MYSQL_HOST"].value == "misp-db"
    assert env["REDIS_HOST"].value == "misp-redis"
    assert env["HOME"].value == "/root"
    # Scenario-fixture lab credentials are reproduction inputs: preserved as
    # secret_fixture values (ACES #471), not redacted.
    assert env["ADMIN_KEY"].value == "JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw"
    assert env["ADMIN_KEY"].value_classification == "secret_fixture"
    assert env["MYSQL_PASSWORD"].value == "misp_db_password"
    assert env["MYSQL_PASSWORD"].value_classification == "secret_fixture"

    published = {(port.host_ip, port.host_port, port.container_port) for port in runtime.network.published_ports}
    assert published == {("0.0.0.0", 8443, 443), ("::", 8443, 443)}

    listeners = {listener.service_listener_id: listener for listener in runtime.service_listeners}
    assert listeners["https-443-ipv4"].scope == "wildcard"
    assert listeners["https-443-ipv4"].published_port_refs[0].host_port == 8443
    assert listeners["misp-zmq-50000-loopback"].scope == "loopback_only"
    assert listeners["supervisor-9001-loopback"].scope == "loopback_only"
    assert listeners["docker-dns-34143-loopback"].scope == "node_local"
    assert listeners["docker-dns-34143-loopback"].service == ""
    assert listeners["php-fpm-unix-socket"].protocol == "unix"

    authority = runtime.identity_authorities[0]
    assert authority.identity_authority_id == "misp-local-authorization"
    subjects = {subject.subject_id: subject for subject in authority.subjects}
    assert subjects["user-admin"].principal_name == "admin@admin.test"
    assert subjects["auth-key-2"].kind == "service_principal"
    assert {s for s in subjects if s.startswith("role-")} == {
        "role-admin",
        "role-org-admin",
        "role-user",
        "role-publisher",
        "role-sync-user",
        "role-read-only",
    }
    assert len(authority.policies) == 6

    app = runtime.applications[0]
    routes = {route.route_id: route for route in app.routes}
    assert app.application_id == "misp-web"
    assert routes["login-get"].path == "/users/login"
    assert routes["restsearch-post"].auth_required is True
    assert routes["restsearch-post"].auth_scheme == "MISP API key in Authorization header"

    platform = runtime.platform_applications[0]
    assert platform.platform_application_id == "misp-threat-intel"
    assert platform.platform_kind == "threat_intel"
    assert platform.product == "MISP"
    assert platform.version == "2.5.36"
    assert len(platform.content_objects) == PLATFORM_CONTENT_OBJECT_COUNT
    assert len(platform.settings) == PLATFORM_SETTING_COUNT
    platform_content = {item.content_object_id: item for item in platform.content_objects}
    assert platform_content["misp-taxonomies"].kind == "taxonomy"
    assert platform_content["misp-taxonomies"].attributes["row_count"] == 165
    assert platform_content["misp-galaxy-clusters"].kind == "galaxy_cluster"
    assert platform_content["misp-galaxy-clusters"].attributes["row_count"] == 49300
    assert platform_content["misp-sharing-groups"].kind == "sharing_group"
    assert platform_content["misp-object-templates"].attributes["row_count"] == 388
    platform_settings = {setting.name: setting for setting in platform.settings}
    assert platform_settings["db_version"].value == "146"
    assert platform_settings["default_role"].provenance == "database"
    assert platform_settings["default_role"].classification == "plain"
    assert "addIPLogging" in platform_settings["update_progress"].value

    content = scenario.content[MISP_CONTENT_ID]
    content_counts = {item.name: item.tags[1] for item in content.items}
    assert content_counts["events"] == "count:0"
    assert content_counts["attributes"] == "count:0"
    assert content_counts["objects"] == "count:0"
    assert content_counts["taxonomies"] == "count:165"
    assert content_counts["galaxy_clusters"] == "count:49300"
    assert content_counts["object_templates"] == "count:388"

    relationships = scenario.relationships
    assert relationships[f"{MISP_REL_PREFIX}misp-connects-mariadb"].properties["auth_method"] == "password"
    assert relationships[f"{MISP_REL_PREFIX}misp-connects-redis"].properties["auth_method"] == "unknown"
    assert (
        relationships[f"{MISP_REL_PREFIX}misp-suricata-sync-queries-misp-api"].properties["tls_verification"]
        == "lab_ca"
    )


def test_techvault_sdl_compiles_with_misp_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments[f"provision.node.{MISP_NODE_ID}"].spec["node"]
    runtime = node["runtime"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(node["source"]["build"]["instructions"]) == DOCKER_HISTORY_ROW_COUNT
    assert len(node["source"]["build"]["layers"]) == IMAGE_LAYER_COUNT
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert len(runtime["service_listeners"]) == SERVICE_LISTENER_COUNT
    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["applications"][0]["application_id"] == "misp-web"
    assert runtime["platform_applications"][0]["platform_application_id"] == "misp-threat-intel"
    assert len(runtime["platform_applications"][0]["settings"]) == PLATFORM_SETTING_COUNT
    assert len(runtime["platform_applications"][0]["content_objects"]) == PLATFORM_CONTENT_OBJECT_COUNT
    assert runtime["identity_authorities"][0]["identity_authority_id"] == "misp-local-authorization"


def test_parity_inventory_cites_misp_inventory_and_aces_sdl():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    row = rows["scen.techvault.misp-inventory"]
    assert row["category"] == "aces_sdl"
    assert "runtime.service_listeners" in row["aces_target"]
    assert "runtime.identity_authorities" in row["aces_target"]
    assert "runtime.platform_applications" in row["aces_target"]
    assert "tests/test_misp_inventory.py" in row["validation_evidence"]
    assert "Brad-Edwards/aces#431/#465 consumed" in row["validation_evidence"]
    # #348 (misp-redis) completed; the misp row now tracks only the remaining #349.
    assert "#349" in row["blocking_followup"]
