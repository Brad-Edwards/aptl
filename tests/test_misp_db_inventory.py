"""Checks for the SCN-010 MISP DB steady-state inventory bundle."""

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


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MISP_DB_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "misp-db"
MISP_DB_DOC_PATH = MISP_DB_DIR / "README.md"
CAPTURE_SCRIPT_PATH = MISP_DB_DIR / "capture-evidence.sh"
LEDGER_PATH = MISP_DB_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = MISP_DB_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:407fccb51e710f34752c1a3ef9b936d1f55f38d4ac7fa043b3759742d266fd9a"
IMAGE_DIGEST = f"mariadb@{IMAGE_ID}"
RUNTIME_PACKAGE_COUNT = 151
TRIVY_FINDING_COUNT = 100
FILESYSTEM_ENTRY_COUNT = 434
FILESYSTEM_CHECKSUM_COUNT = 416
LOCAL_IDENTITY_USER_COUNT = 20
LOCAL_IDENTITY_GROUP_COUNT = 40
DOCKER_HISTORY_ROW_COUNT = 23
IMAGE_LAYER_COUNT = 8
RUNTIME_PROCESS_COUNT = 1
RUNTIME_ENV_COUNT = 11
SERVICE_LISTENER_COUNT = 5
DATABASE_COUNT = 5
DATABASE_TABLE_COUNT = 235
MISP_TABLE_COUNT = 103
DATABASE_ROLE_COUNT = 7
DATABASE_SETTING_COUNT = 15
SOFTWARE_COMPONENT_COUNT = 3
LEDGER_FACT_COUNT = 25

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.misp-db.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.misp-db.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.misp-db-data.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
    "language-manifests.txt",
    "mariadb-state.txt",
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
    "participant-discovery.misp.txt",
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

_PASSWORD_ENV_SUFFIX = "PASS" "WORD"
_MISP_FIXTURE_PREFIX = "mi" "sp"

RAW_SECRET_PATTERNS = (
    r"misp_db_password",
    r"misp_root_password",
    r"redispassword",
    rf"MYSQL_{_PASSWORD_ENV_SUFFIX}={_MISP_FIXTURE_PREFIX}",
    rf"MYSQL_ROOT_{_PASSWORD_ENV_SUFFIX}={_MISP_FIXTURE_PREFIX}",
    r"BEGIN .*PRIVATE KEY",
)


@pytest.fixture(scope="module")
def legacy_scenario():
    return load_legacy_techvault_sdl(str(TECHVAULT_SDL_PATH))


@pytest.fixture(scope="module")
def compiled_runtime_model():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    return compile_runtime_model(parse_sdl_file(TECHVAULT_SDL_PATH))


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


def _section(text: str, name: str) -> list[str]:
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[^-\n][^\n]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _runtime_baseline_section(name: str) -> list[str]:
    return _section((EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8"), name)


def _mariadb_section(name: str) -> list[str]:
    return _section((EVIDENCE_DIR / "mariadb-state.txt").read_text(encoding="utf-8"), name)


def _filesystem_tree_rows() -> list[list[str]]:
    rows = []
    for line in _evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines():
        parts = line.split("\t")
        if len(parts) == 1:
            parts = line.split("\\t")
        rows.append(parts)
    return rows


def _unique_osquery_listeners() -> set[tuple[str, str, str, str, str]]:
    rows = _json_file("osquery-listening-ports.json")["rows"]
    return {
        (row["address"], row["path"], row["port"], row["protocol"], row["socket"])
        for row in rows
    }


def test_misp_db_inventory_note_declares_scope_and_realization_caveats():
    text = MISP_DB_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #347",
        "aptl-misp-db",
        "mariadb:10.11",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run `aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "Brad-Edwards/aces#388",
        "ACES #431",
        "No known ACES expressivity gap remains",
        "runtime.database_services",
        "2,509,058 warninglist entries",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"MISP DB inventory note missing scope markers: {missing}"


def test_misp_db_capture_script_pins_toolchain_and_database_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        'yq -o=json \'.services."misp-db"\'',
        "select @@version",
        "query information_schema",
        "participant-discovery.misp.txt",
        "filesystem-tree.txt.gz",
        "filesystem-checksums.txt.xz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_misp_db_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(MISP_DB_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 347
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["misp-db.runtime.service-listeners"] == "encoded_with_caveat"
    assert dispositions["misp-db.database.databases-schemas-tables"] == "encoded_with_caveat"
    assert dispositions["misp-db.database.roles"] == "encoded_with_caveat"
    assert dispositions["misp-db.database.table-cardinalities"] == "encoded_with_caveat"
    fields = {fact["id"]: set(fact["aces"]["fields"]) for fact in ledger["facts"]}
    assert "nodes.techvault.misp-db.runtime.database_services.misp-mariadb.roles" in fields["misp-db.database.roles"]
    assert "relationships.misp-connects-mariadb.database_access" in fields["misp-db.relationship.misp"]


def test_misp_db_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(MISP_DB_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_misp_db_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_misp_db_evidence_sha256_manifest_matches_files():
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


def test_misp_db_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_misp_db_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_misp_db_runtime_evidence_counts_and_caveats():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["docker-entrypoint.sh"]
    assert image["Config"]["Cmd"] == ["mariadbd"]
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["HostConfig"]["Memory"] == 536870912
    assert container["HostConfig"]["MemorySwap"] == 1073741824
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_filesystem_tree_rows()) == FILESYSTEM_ENTRY_COUNT
    assert all(len(row) == 12 for row in _filesystem_tree_rows())
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz").splitlines()) == FILESYSTEM_CHECKSUM_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_json_file("trivy-vulnerabilities.json.gz")["Metadata"]["Layers"]) == IMAGE_LAYER_COUNT
    assert len(_runtime_baseline_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_runtime_baseline_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(_runtime_baseline_section("environment")) == RUNTIME_ENV_COUNT
    assert len(_json_file("osquery-processes.json")["rows"]) == RUNTIME_PROCESS_COUNT
    assert len(_unique_osquery_listeners()) == SERVICE_LISTENER_COUNT


def test_misp_db_mariadb_state_evidence_captures_expected_logical_state():
    version = _mariadb_section("mariadb-version")
    databases = _mariadb_section("databases")[1:]
    users = _mariadb_section("users")[1:]
    schema_tables = _mariadb_section("schema-tables")[1:]
    counts = {
        row.split("\t")[0]: int(row.split("\t")[1])
        for row in _mariadb_section("misp-table-counts")[1:]
    }
    settings = {row.split("\t", maxsplit=1)[0]: row.split("\t", maxsplit=1)[1] for row in _mariadb_section("settings")[1:] if "\t" in row}

    assert "10.11.16-MariaDB-ubu2204" in version[1]
    assert set(databases) == {"information_schema", "misp", "mysql", "performance_schema", "sys"}
    assert len(users) == DATABASE_ROLE_COUNT
    assert len(schema_tables) == DATABASE_TABLE_COUNT
    assert counts["events"] == 0
    assert counts["attributes"] == 0
    assert counts["objects"] == 0
    assert counts["feeds"] == 2
    assert counts["taxonomies"] == 165
    assert counts["galaxy_clusters"] == 56341
    assert counts["galaxy_elements"] == 321235
    assert counts["warninglists"] == 122
    assert counts["warninglist_entries"] == 2509058
    assert settings["port"] == "3306"
    assert settings["datadir"] == "/var/lib/mysql/"
    assert settings["socket"] == "/run/mysqld/mysqld.sock"
    assert settings["skip_networking"] == "OFF"


def test_misp_db_participant_discovery_records_expected_reachability():
    misp = (EVIDENCE_DIR / "participant-discovery.misp.txt").read_text(encoding="utf-8")
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "172.20.0.17     misp-db" in misp
    assert "misp-db:3306 reachable" in misp
    assert "database_name" in misp
    assert "misp" in misp
    assert "Network is unreachable" in kali


def test_misp_db_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert syft_version["application"] == "syft"


def test_techvault_sdl_encodes_misp_db_inventory_surfaces(legacy_scenario):
    node = legacy_scenario["nodes"]["misp-db"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["name"] == "mariadb"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Ubuntu 22.04.5 LTS (Jammy Jellyfish)"
    assert build["base_image"] == "ubuntu:jammy"
    assert build["dockerfile_path"] == "upstream:mariadb/mariadb-docker/10.11"
    assert len(build["instructions"]) == DOCKER_HISTORY_ROW_COUNT
    assert len(build["layers"]) == IMAGE_LAYER_COUNT
    assert build["source_inputs"][0]["source_path"] == "docker-compose.yml"
    assert build["attestation"]["status"] == "absent"

    services = {service["name"]: service["port"] for service in node["services"]}
    assert services == {"mariadb": 3306}

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert len(runtime["service_listeners"]) == SERVICE_LISTENER_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT

    env = {item["name"]: item for item in runtime["environment"]}
    assert env["MYSQL_DATABASE"]["value"] == "misp"
    assert env["MYSQL_USER"]["value"] == "misp"
    assert env["MYSQL_PASSWORD"]["value_classification"] == "redacted"
    assert env["MYSQL_ROOT_PASSWORD"]["value_classification"] == "redacted"
    assert env["HOSTNAME"]["provenance"] == "runtime"

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert mounts["/var/lib/mysql"]["source"] == "aptl_misp_db_data"
    assert mounts["/var/lib/mysql"]["source_kind"] == "volume"

    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert filesystem["/etc/mysql/mariadb.conf.d/50-server.cnf"]["content_digest"] == (
        "730f1a7decf874c1c197371bc0e189eca59ab02d1b79756814d4e1bc5a6a86a5"
    )
    assert filesystem["/var/lib/mysql/misp/users.frm"]["content_digest"] == (
        "95c5ce80f2aa71ca9f8a69053dff7c73d8db7e58b0af810f60552a2fa07ee2ee"
    )
    assert filesystem["/var/lib/mysql/mysql/global_priv.MAD"]["sensitivity"] == "operator_secret"
    assert filesystem["/var/lib/mysql/mysql/global_priv.MAD"]["content_digest"] == ""

    listeners = {listener["service_listener_id"]: listener for listener in runtime["service_listeners"]}
    assert listeners["mariadb-3306-ipv4"]["scope"] == "wildcard"
    assert listeners["mariadb-3306-ipv6"]["address_family"] == "ipv6"
    assert listeners["mariadb-unix-socket"]["protocol"] == "unix"
    assert listeners["docker-dns-42583-tcp"]["scope"] == "node_local"
    assert listeners["docker-dns-51888-udp"]["protocol"] == "udp"

    network = runtime["network"]
    assert network["published_ports"] == []
    endpoint = network["endpoints"][0]
    assert endpoint["network"] == "security-net"
    assert endpoint["ip_address"] == "172.20.0.17"
    assert endpoint["aliases"] == ["aptl-misp-db", "misp-db"]
    assert endpoint["dns_names"] == ["aptl-misp-db", "misp-db", "1574ba5c2bb2"]


def test_techvault_sdl_encodes_misp_db_database_state_and_relationship(legacy_scenario):
    runtime = legacy_scenario["nodes"]["misp-db"]["runtime"]
    database_service = runtime["database_services"][0]
    assert database_service["database_service_id"] == "misp-mariadb"
    assert database_service["service"] == "mariadb"
    assert database_service["engine"] == "mariadb"
    assert database_service["protocol"] == "mysql"
    assert database_service["version"] == "10.11.16-MariaDB-ubu2204"
    assert {listener["address"] for listener in database_service["listeners"]} == {
        "0.0.0.0",
        "::",
        "/run/mysqld/mysqld.sock",
    }

    databases = {database["database_id"]: database for database in database_service["databases"]}
    assert set(databases) == {"information_schema", "misp", "mysql", "performance_schema", "sys"}
    assert databases["misp"]["origin"] == "scenario"
    assert databases["information_schema"]["schemas"] == []

    misp_tables = {table["name"]: table for table in databases["misp"]["schemas"][0]["tables"]}
    mysql_tables = {table["name"]: table for table in databases["mysql"]["schemas"][0]["tables"]}
    sys_tables = {table["name"]: table for table in databases["sys"]["schemas"][0]["tables"]}
    assert len(misp_tables) == MISP_TABLE_COUNT
    assert sum(len(database["schemas"][0]["tables"]) if database["schemas"] else 0 for database in databases.values()) == DATABASE_TABLE_COUNT
    assert misp_tables["events"]["description"].endswith("TABLE_ROWS=0.")
    assert misp_tables["warninglist_entries"]["description"].endswith("TABLE_ROWS=2509058.")
    assert mysql_tables["global_priv"]["description"].startswith("Observed BASE TABLE")
    assert "x$wait_classes_global_by_latency" in sys_tables

    roles = {role["role_id"]: role for role in database_service["roles"]}
    assert roles["misp"]["name"] == "misp@%"
    assert roles["misp"]["role_type"] == "application"
    assert roles["root-anyhost"]["role_type"] == "admin"
    assert "Super_priv=Y" in roles["root-anyhost"]["description"]
    assert roles["healthcheck-localhost"]["role_type"] == "service"
    assert len(roles) == DATABASE_ROLE_COUNT

    settings = {setting["name"]: setting for setting in database_service["settings"]}
    assert len(settings) == DATABASE_SETTING_COUNT
    assert settings["port"]["value"] == "3306"
    assert settings["datadir"]["value"] == "/var/lib/mysql/"
    assert settings["sql_mode"]["value"].startswith("STRICT_TRANS_TABLES")

    content = legacy_scenario["content"]["misp-db-table-cardinalities"]
    content_counts = {item["name"]: item["tags"][1] for item in content["items"]}
    assert content_counts["misp.events"] == "count:0"
    assert content_counts["misp.attributes"] == "count:0"
    assert content_counts["misp.objects"] == "count:0"
    assert content_counts["misp.warninglist_entries"] == "count:2509058"
    assert len(content_counts) == MISP_TABLE_COUNT

    relationship = legacy_scenario["relationships"]["misp-connects-mariadb"]
    assert relationship["source"] == "nodes.misp.runtime.applications.misp-web"
    assert relationship["target"] == "nodes.misp-db.runtime.database_services.misp-mariadb.databases.misp"
    assert relationship["database_access"]["role_ref"] == "misp"
    assert relationship["database_access"]["auth_method"] == "password"


def test_misp_db_runtime_local_identity_matches_passwd_and_group_evidence(legacy_scenario):
    local_identity = legacy_scenario["nodes"]["misp-db"]["runtime"]["local_identity"]
    encoded_users = {user["username"]: user for user in local_identity["users"]}
    encoded_groups = {group["name"]: group for group in local_identity["groups"]}

    group_rows = {}
    gid_names = {}
    for line in _runtime_baseline_section("groups"):
        name, _password, gid, members = line.split(":")
        member_list = [member for member in members.split(",") if member]
        group_rows[name] = {"gid": int(gid), "members": member_list}
        gid_names[int(gid)] = name

    assert set(encoded_groups) == set(group_rows)
    for name, expected in group_rows.items():
        assert encoded_groups[name]["gid"] == expected["gid"]
        assert encoded_groups[name]["members"] == expected["members"]

    passwd_rows = {}
    for line in _runtime_baseline_section("users"):
        username, _password, uid, gid, gecos, home, shell = line.split(":")
        passwd_rows[username] = {
            "uid": int(uid),
            "primary_gid": int(gid),
            "primary_group": gid_names[int(gid)],
            "gecos": gecos,
            "home": home,
            "shell": shell,
            "no_login": shell.endswith("nologin"),
        }

    assert set(encoded_users) == set(passwd_rows)
    for username, expected in passwd_rows.items():
        encoded = encoded_users[username]
        for field, value in expected.items():
            if field == "gecos" and not value:
                assert encoded.get(field, "") == ""
            else:
                assert encoded[field] == value

    assert local_identity["sudo_rules"] == []


def test_misp_db_local_and_database_role_accounts_are_encoded(legacy_scenario):
    accounts = legacy_scenario["accounts"]
    account_usernames = {
        account["username"]
        for name, account in accounts.items()
        if name.startswith("misp-db-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames <= account_usernames
    assert accounts["misp-db-role-misp"]["password_strength"] == "weak"
    assert accounts["misp-db-role-misp"]["auth_method"] == "password"
    assert accounts["misp-db-role-root"]["password_strength"] == "weak"
    assert accounts["misp-db-role-healthcheck"]["auth_method"] == "password"


def test_techvault_sdl_compiles_with_misp_db_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.misp-db"].spec["node"]
    runtime = node["runtime"]
    database_service = runtime["database_services"][0]

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
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["health"]["status"] == "healthy"
    assert database_service["engine"] == "mariadb"
    assert database_service["protocol"] == "mysql"
    assert {database["database_id"] for database in database_service["databases"]} == {
        "information_schema",
        "misp",
        "mysql",
        "performance_schema",
        "sys",
    }
    assert {role["role_id"] for role in database_service["roles"]} >= {"misp", "root-anyhost"}


def test_parity_inventory_cites_misp_db_inventory_and_updates_misp_followups():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    misp_db = rows["scen.techvault.misp-db-inventory"]
    assert misp_db["category"] == "aces_sdl"
    assert misp_db["blocking_followup"] == "n/a"
    assert "runtime.database_services" in misp_db["aces_target"]
    assert "docs/aces/inventory/misp-db/" in misp_db["validation_evidence"]
    assert "tests/test_misp_db_inventory.py" in misp_db["validation_evidence"]
    assert "Brad-Edwards/aces#388/#431/#465 consumed" in misp_db["validation_evidence"]

    misp = rows["scen.techvault.misp-inventory"]
    assert "#347" not in misp["blocking_followup"]
    assert "#348/#349" in misp["blocking_followup"]
