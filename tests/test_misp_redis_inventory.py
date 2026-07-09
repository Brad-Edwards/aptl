"""Checks for the SCN-010 MISP Redis steady-state inventory bundle."""

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
REDIS_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "misp-redis"
REDIS_DOC_PATH = REDIS_DIR / "README.md"
CAPTURE_SCRIPT_PATH = REDIS_DIR / "capture-evidence.sh"
LEDGER_PATH = REDIS_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = REDIS_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:7aec734b2bb298a1d769fd8729f13b8514a41bf90fcdd1f38ec52267fbaa8ee6"
IMAGE_DIGEST = f"redis@{IMAGE_ID}"
RUNTIME_PACKAGE_COUNT = 17
TRIVY_FINDING_COUNT = 101
FILESYSTEM_TREE_ENTRY_COUNT = 97
FILESYSTEM_CHECKSUM_COUNT = 51
FILESYSTEM_INVENTORY_COUNT = 18
LOCAL_IDENTITY_USER_COUNT = 18
LOCAL_IDENTITY_GROUP_COUNT = 36
DOCKER_HISTORY_ROW_COUNT = 17
IMAGE_LAYER_COUNT = 8
RUNTIME_PROCESS_COUNT = 1
RUNTIME_ENV_COUNT = 5
SERVICE_LISTENER_COUNT = 4
SOFTWARE_COMPONENT_COUNT = 5
DATASTORE_PARTITION_COUNT = 3
DATASTORE_SETTING_COUNT = 18
LEDGER_FACT_COUNT = 26

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.misp-redis.json",
    "docker-buildx-imagetools.attestation-amd64.raw.json",
    "docker-buildx-imagetools.image.raw.json",
    "docker-buildx-imagetools.image.txt",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-logs.misp-redis.txt",
    "docker-network.aptl-security.json",
    "docker-top.txt",
    "docker-version.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt.xz",
    "filesystem-tree.txt.gz",
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
    "redis-manifest.txt",
    "redis-state.txt",
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

# The lab Redis auth fixture must never be committed raw; split so this detection
# pattern is not itself a committed copy of the literal value.
# The Redis auth fixture is a DISCLOSED scenario realization fact (the
# provisioning input that reproduces this asset), preserved in the evidence and
# encoded as a secret_fixture value in the SDL (ACES #471) -- it is NOT a leak.
# Only real operator-secret shapes are forbidden in committed evidence.
_REDIS_FIXTURE = "redis" "password"

RAW_SECRET_PATTERNS = (
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


def _section(text: str, name: str) -> list[str]:
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[^-\n][^\n]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _runtime_baseline_section(name: str) -> list[str]:
    return _section((EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8"), name)


def _redis_section(name: str) -> list[str]:
    return _section((EVIDENCE_DIR / "redis-state.txt").read_text(encoding="utf-8"), name)


def _redis_datatype_census() -> dict[int, dict[str, int]]:
    # The datatype census is the last section and has nested --dbN-- markers, so
    # read it to EOF rather than via _section (which stops at the first marker).
    blob = (EVIDENCE_DIR / "redis-state.txt").read_text(encoding="utf-8").split(
        "--datatype-census--\n", 1
    )[1]
    census: dict[int, dict[str, int]] = {}
    cur = None
    for line in blob.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        marker = re.match(r"^--db(\d+)--$", line)
        if marker:
            cur = int(marker.group(1))
            census[cur] = {}
        elif cur is not None:
            count, kind = line.split()
            census[cur][kind] = int(count)
    return census


def _filesystem_tree_rows() -> list[list[str]]:
    return [
        line.split("\t")
        for line in _evidence_text(EVIDENCE_DIR / "filesystem-tree.txt.gz").splitlines()
    ]


def _unique_osquery_listeners() -> set[tuple[str, str, str, str, str]]:
    rows = _json_file("osquery-listening-ports.json")["rows"]
    return {
        (row["address"], row["path"], row["port"], row["protocol"], row["socket"])
        for row in rows
    }


def test_misp_redis_inventory_note_declares_scope_and_realization_caveats():
    text = REDIS_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue 348",
        "aptl-misp-redis",
        "redis:7-alpine",
        IMAGE_DIGEST,
        "non-destructive",
        "did not run `aptl lab stop -v && aptl lab start`",
        "not as clean-lab rebuild proof",
        "runtime.datastore_services",
        "redis_acl",
        "ACES #431",
        "No known ACES expressivity gap remains",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"MISP Redis inventory note missing scope markers: {missing}"


def test_misp_redis_capture_script_pins_toolchain_and_redis_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "REDISCLI_AUTH",
        "redis-cli INFO server",
        "ACL LIST",
        "datatype-census",
        "filesystem-tree.txt.gz",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    # The capture script must not authenticate via a raw -a argv form.
    assert "redis-cli -a " not in text
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_misp_redis_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(REDIS_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 348
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "captured"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["misp-redis.datastore.service"] == "encoded"
    assert dispositions["misp-redis.datastore.logical-dbs"] == "encoded_with_caveat"
    assert dispositions["misp-redis.datastore.acl"] == "encoded_with_caveat"
    fields = {fact["id"]: set(fact["aces"]["fields"]) for fact in ledger["facts"]}
    assert (
        "nodes.techvault.misp-redis.runtime.datastore_services.misp_redis"
        in fields["misp-redis.datastore.service"]
    )
    assert (
        "nodes.techvault.misp-redis.runtime.app_authorizations.misp_redis_acl"
        in fields["misp-redis.datastore.acl"]
    )


def test_misp_redis_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(REDIS_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_misp_redis_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_misp_redis_evidence_sha256_manifest_matches_files():
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


def test_misp_redis_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_misp_redis_evidence_does_not_commit_raw_operator_secrets():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw operator-secret material leaked into evidence: {offenders}"


def test_misp_redis_evidence_preserves_disclosed_auth_fixture():
    # The Redis auth fixture is scenario realization content needed to reproduce
    # this asset; it must be preserved verbatim, not redacted.
    compose = _json_file("compose-service.misp-redis.json")
    assert compose["command"] == f"redis-server --requirepass {_REDIS_FIXTURE}"
    container = _json_file("docker-inspect.container.json")[0]
    assert container["Config"]["Cmd"] == ["redis-server", "--requirepass", _REDIS_FIXTURE]


def test_misp_redis_runtime_evidence_counts_and_caveats():
    image = _json_file("docker-inspect.image.json")[0]
    container = _json_file("docker-inspect.container.json")[0]

    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["docker-entrypoint.sh"]
    assert image["Config"]["Cmd"] == ["redis-server"]
    assert container["State"]["Status"] == "running"
    assert container["State"].get("Health") is None  # no Compose healthcheck
    assert container["HostConfig"]["Memory"] == 134217728
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len(_filesystem_tree_rows()) == FILESYSTEM_TREE_ENTRY_COUNT
    assert all(len(row) == 12 for row in _filesystem_tree_rows())
    assert len(_evidence_text(EVIDENCE_DIR / "filesystem-checksums.txt.xz").splitlines()) == FILESYSTEM_CHECKSUM_COUNT
    assert len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines()) == DOCKER_HISTORY_ROW_COUNT
    assert len(_json_file("trivy-vulnerabilities.json.gz")["Metadata"]["Layers"]) == IMAGE_LAYER_COUNT
    assert len(_runtime_baseline_section("users")) == LOCAL_IDENTITY_USER_COUNT
    assert len(_runtime_baseline_section("groups")) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(_json_file("osquery-processes.json")["rows"]) == RUNTIME_PROCESS_COUNT
    assert len(_unique_osquery_listeners()) == SERVICE_LISTENER_COUNT


def test_misp_redis_state_evidence_captures_expected_logical_state():
    server = {line.split(":", 1)[0]: line.split(":", 1)[1] for line in _redis_section("server")}
    config = {row.split("\t")[0]: (row.split("\t")[1] if "\t" in row else "") for row in _redis_section("config")}
    keyspace_dbs = {re.match(r"^(db\d+):", line).group(1) for line in _redis_section("keyspace")}

    assert server["redis_version"] == "7.4.8"
    assert server["redis_mode"] == "standalone"
    assert config["dir"] == "/data"
    assert config["port"] == "6379"
    assert config["databases"] == "16"
    assert config["maxmemory-policy"] == "noeviction"
    assert config["appendonly"] == "no"
    assert config["bind"] == "* -::*"
    assert keyspace_dbs == {"db0", "db1", "db13"}
    assert _redis_section("acl-whoami") == ["default"]
    acl_list = "\n".join(_redis_section("acl-list"))
    assert "user default on" in acl_list
    assert "+@all" in acl_list


def test_misp_redis_participant_discovery_records_expected_reachability():
    misp = (EVIDENCE_DIR / "participant-discovery.misp.txt").read_text(encoding="utf-8")
    kali = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "172.20.0.2      misp-redis" in misp
    assert "misp-redis:6379 reachable" in misp
    assert "Network is unreachable" in kali


def test_misp_redis_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert syft_version["application"] == "syft"


def test_techvault_sdl_encodes_misp_redis_inventory_surfaces(legacy_scenario):
    node = legacy_scenario["nodes"]["misp-redis"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["name"] == "redis"
    assert node["source"]["version"] == IMAGE_DIGEST
    assert node["os_version"] == "Alpine Linux 3.21.7"
    assert build["base_image"] == "alpine:3.21.7"
    assert build["dockerfile_path"] == "upstream:redis/docker-library/7/alpine"
    assert len(build["instructions"]) == DOCKER_HISTORY_ROW_COUNT
    assert len(build["layers"]) == IMAGE_LAYER_COUNT
    assert build["source_inputs"][0]["source_path"] == "docker-compose.yml"
    assert build["attestation"]["status"] == "present"

    services = {service["name"]: service["port"] for service in node["services"]}
    assert services == {"redis": 6379}

    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_INVENTORY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["processes"]) == RUNTIME_PROCESS_COUNT
    assert len(runtime["environment"]) == RUNTIME_ENV_COUNT
    assert len(runtime["service_listeners"]) == SERVICE_LISTENER_COUNT
    assert len(runtime["software_components"]) == SOFTWARE_COMPONENT_COUNT
    assert runtime["database_services"] == []  # Redis is NOT relational

    env = {item["name"]: item for item in runtime["environment"]}
    assert env["REDIS_VERSION"]["value"] == "7.4.8"

    process = runtime["processes"][0]
    assert process["name"] == "redis-server"
    assert process["user"] == "redis"

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert mounts["/data"]["source_kind"] == "volume"
    assert mounts["/data"]["source"] == "anonymous"

    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert filesystem["/usr/local/bin/redis-server"]["content_digest"] == (
        "a5fed84c8d1d871609f9faa8b85a8b4ac79d98f5e9a3d5e4939af56223d6061c"
    )
    assert filesystem["/data/dump.rdb"]["sensitivity"] == "secret_fixture"
    assert filesystem["/data/dump.rdb"]["content_digest"] == (
        "716192aac3da66017ede5dbdb61ebb039ccc842573e042a42e63af218595a54d"
    )
    assert filesystem["/etc/shadow"]["sensitivity"] == "secret_fixture"
    assert filesystem["/etc/shadow"]["content_digest"] == (
        "ca53a080cdd6f1d90932ebd6f4ba51624964c0a8487f9355547291d055993b02"
    )

    listeners = {listener["service_listener_id"]: listener for listener in runtime["service_listeners"]}
    assert listeners["redis-6379-ipv4"]["scope"] == "wildcard"
    assert listeners["redis-6379-ipv6"]["address_family"] == "ipv6"
    assert listeners["docker-embedded-dns-tcp"]["scope"] == "loopback_only"
    assert listeners["docker-embedded-dns-udp"]["protocol"] == "udp"

    network = runtime["network"]
    assert network["published_ports"] == []
    endpoint = network["endpoints"][0]
    assert endpoint["ip_address"] == "172.20.0.2"
    assert "misp-redis" in endpoint["aliases"]


def test_techvault_sdl_encodes_misp_redis_datastore_and_acl(legacy_scenario):
    runtime = legacy_scenario["nodes"]["misp-redis"]["runtime"]
    datastore = runtime["datastore_services"][0]

    assert datastore["datastore_service_id"] == "misp_redis"
    assert datastore["engine"] == "redis"
    assert datastore["data_model"] == "key_value"
    assert datastore["protocol"] == "resp"
    assert datastore["version"] == "7.4.8"
    assert datastore["authorization_ref"] == "misp_redis_acl"
    assert datastore["transport_security"]["mode"] == "none"

    persistence = datastore["persistence"]
    assert persistence["rdb_save_points"] == ["save 3600 1", "save 300 100", "save 60 10000"]
    assert persistence["aof"] is False
    assert persistence["eviction"] == "noeviction"
    assert persistence["maxmemory"] == "0"

    partitions = {p["partition_id"]: p for p in datastore["partitions"]}
    assert len(partitions) == DATASTORE_PARTITION_COUNT
    assert all(p["kind"] == "logical_db" for p in partitions.values())
    assert set(partitions) == {"redis_db0", "redis_db1", "redis_db13"}
    # Per-DB datatype census is volatile MISP-driven state; assert the SDL
    # matches the captured evidence snapshot rather than hard-coding drift-prone
    # counts. (db0/db13 are key-value string/zset-bearing at capture time.)
    evidence_census = _redis_datatype_census()
    sdl_census = {p["partition_id"]: p["datatype_census"] for p in datastore["partitions"]}
    assert sdl_census == {f"redis_db{db}": census for db, census in evidence_census.items()}
    assert set(partitions["redis_db13"]["datatype_census"]) == {"zset", "string", "set", "hash"}

    settings = {s["name"]: s for s in datastore["settings"]}
    assert len(datastore["settings"]) == DATASTORE_SETTING_COUNT
    assert settings["databases"]["value"] == "16"
    assert settings["maxmemory-policy"]["value"] == "noeviction"
    # The requirepass fixture is a disclosed scenario realization fact (ACES
    # #471): its value is preserved in the setting value, NOT redacted.
    assert settings["requirepass"]["value"] == _REDIS_FIXTURE
    assert settings["requirepass"]["classification"] == "plain"

    acl = runtime["app_authorizations"][0]
    assert acl["app_authorization_id"] == "misp_redis_acl"
    assert acl["resource_vocabulary"] == "redis_acl"
    principal = acl["principals"][0]
    assert principal["kind"] == "user"
    assert principal["name"] == "default"
    assert principal["credential_classification"] == "none"
    grant = acl["permission_grants"][0]
    assert grant["resource_kind"] == "redis_acl"
    assert grant["actions"] == ["+@all"]
    assert grant["resource_patterns"] == ["~*", "&*"]


def test_misp_redis_runtime_local_identity_matches_passwd_and_group_evidence(legacy_scenario):
    local_identity = legacy_scenario["nodes"]["misp-redis"]["runtime"]["local_identity"]
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
            assert encoded[field] == value

    assert local_identity["sudo_rules"] == []
    assert "redis" in encoded_users
    assert encoded_users["redis"]["uid"] == 999


def test_techvault_sdl_compiles_with_misp_redis_runtime_fields(compiled_runtime_model):
    node = compiled_runtime_model.node_deployments["provision.node.techvault.misp-redis"].spec["node"]
    runtime = node["runtime"]
    datastore = runtime["datastore_services"][0]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(node["source"]["build"]["instructions"]) == DOCKER_HISTORY_ROW_COUNT
    assert len(node["source"]["build"]["layers"]) == IMAGE_LAYER_COUNT
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_INVENTORY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["service_listeners"]) == SERVICE_LISTENER_COUNT
    assert runtime["container"]["runtime_name"] == "runc"
    assert datastore["engine"] == "redis"
    assert datastore["data_model"] == "key_value"
    assert {p["partition_id"] for p in datastore["partitions"]} == {"redis_db0", "redis_db1", "redis_db13"}
    assert runtime["app_authorizations"][0]["resource_vocabulary"] == "redis_acl"


def test_parity_inventory_cites_misp_redis_inventory_and_updates_misp_followups():
    rows = {row["id"]: row for row in yaml.safe_load(PARITY_PATH.read_text())["rows"]}
    redis = rows["scen.techvault.misp-redis-inventory"]
    assert redis["category"] == "aces_sdl"
    assert redis["blocking_followup"] == "n/a"
    assert "runtime.datastore_services" in redis["aces_target"]
    assert "runtime.app_authorizations" in redis["aces_target"]
    assert "docs/aces/inventory/misp-redis/" in redis["validation_evidence"]
    assert "tests/test_misp_redis_inventory.py" in redis["validation_evidence"]
    assert "Brad-Edwards/aces#431 consumed" in redis["validation_evidence"]

    misp = rows["scen.techvault.misp-inventory"]
    assert "#348" not in misp["blocking_followup"]
    assert "#349" in misp["blocking_followup"]
