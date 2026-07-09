"""Checks for the SCN-010 db steady-state inventory bundle."""

import hashlib
import json
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
DB_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "db"
DB_DOC_PATH = DB_DIR / "README.md"
LEDGER_PATH = DB_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = DB_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50"
IMAGE_DIGEST = f"postgres@{IMAGE_ID}"

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.db.json",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-internal.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.db-data.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "language-manifests.txt",
    "os-packages.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "trivy-version.txt",
    "trivy-vulnerabilities.json",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}

SECRET_NEEDLES = (
    "POSTGRES_PASSWORD=techvault_db_pass",
    '"POSTGRES_PASSWORD": "techvault_db_pass"',
)


def _json_file(name: str):
    with (EVIDENCE_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def _yaml_file(path: Path):
    if path == TECHVAULT_SDL_PATH:
        return load_legacy_techvault_sdl(str(path))
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _postgres_role_rows() -> dict[str, dict[str, bool]]:
    rows = {}
    for line in _runtime_baseline_section("roles"):
        name, is_superuser, can_create_db, can_create_role, can_login = line.split(":")
        rows[name] = {
            "is_superuser": is_superuser == "true",
            "can_create_db": can_create_db == "true",
            "can_create_role": can_create_role == "true",
            "can_login": can_login == "true",
        }
    return rows


def test_db_inventory_note_declares_scope_and_evidence():
    text = DB_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #331",
        "aptl-db",
        "upstream-image",
        "already-running local lab",
        "did not run",
        "aptl lab stop -v && aptl lab start",
        "postgres:16-alpine",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "Brad-Edwards/aces#388",
        "No known ACES expressivity gap remains",
        "capture boundary",
        "not as clean-lab rebuild proof",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"DB inventory note missing scope markers: {missing}"


def test_db_mapping_ledger_validates_and_tracks_gap_handoff():
    result = validate_mapping_ledger(DB_DIR)
    assert result.ok, result.errors
    assert result.fact_count == 18
    assert result.encoded_count == 18
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    assert len(ledger["correspondence_checks"]) == 2
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    fields = {fact["id"]: set(fact["aces"]["fields"]) for fact in ledger["facts"]}
    assert dispositions["db.image.identity"] == "encoded"
    assert dispositions["db.build.recipe"] == "encoded"
    assert dispositions["db.runtime.filesystem-inventory"] == "encoded_with_caveat"
    assert dispositions["db.runtime.vulnerability-scan"] == "encoded"
    assert dispositions["db.postgres.logical-state"] == "encoded"
    assert "nodes.techvault.db.runtime.database_services.databases" in fields["db.postgres.logical-state"]
    assert "nodes.techvault.db.runtime.database_services.roles" in fields["db.postgres.logical-state"]
    assert "relationships.webapp-connects-db.database_access" in fields["db.relationships"]


def test_db_gap_report_surfaces_remaining_aces_gaps_only():
    report = gap_report(DB_DIR)
    assert report["gaps"] == []
    assert not report["triage_needed"]


def test_db_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_db_evidence_sha256_manifest_matches_files():
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


def test_db_evidence_captures_raw_postgres_fixture_password():
    compose = _json_file("compose-service.db.json")
    container = _json_file("docker-inspect.container.json")[0]
    runtime = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    inspect_env = dict(item.split("=", 1) for item in container["Config"]["Env"])

    assert compose["environment"]["POSTGRES_PASSWORD"] == "techvault_db_pass"
    assert inspect_env["POSTGRES_PASSWORD"] == "techvault_db_pass"
    assert "POSTGRES_PASSWORD=techvault_db_pass" in runtime
    assert "<REDACTED" not in json.dumps(compose)
    assert "<REDACTED" not in json.dumps(container)
    assert "<REDACTED" not in runtime


def test_db_container_runtime_state_and_redaction_boundary():
    container = _json_file("docker-inspect.container.json")[0]
    env = "\n".join(container["Config"]["Env"])

    assert container["Name"] == "/aptl-db"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "db.techvault.local"
    assert container["HostConfig"]["Memory"] == 268435456
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert "aptl_db_data:/var/lib/postgresql/data:rw" in container["HostConfig"]["Binds"]
    assert re.search(r"^POSTGRES_PASSWORD=techvault_db_pass$", env, re.MULTILINE)


def test_db_image_identity_and_source_package_are_recorded():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["docker-entrypoint.sh"]
    assert image["Config"]["Cmd"] == ["postgres"]
    assert "5432/tcp" in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 11

    source_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(
        encoding="utf-8"
    )
    assert "containers/db/init/01-schema.sql" in source_checksums
    assert "containers/db/init/02-seed-data.sql" in source_checksums


def test_db_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        "Alpine Linux v3.23",
        "postgres (PostgreSQL) 16.13",
        "0.0.0.0:5432",
        ":::5432",
        "postgres: logger",
        "postgres: checkpointer",
        "logging_collector=on",
        "log_statement=all",
        "public.users",
        "public.audit_log",
        "POSTGRES_PASSWORD=techvault_db_pass",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_db_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)

    assert counts == dict(computed)
    assert sum(counts.values()) == len(vulnerabilities)
    assert len(vulnerabilities) == 34
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)


def test_techvault_sdl_encodes_db_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    db = data["nodes"]["db"]
    runtime = db["runtime"]
    build = db["source"]["build"]

    assert db["source"]["name"] == "postgres"
    assert db["source"]["version"] == IMAGE_DIGEST
    assert build["base_image"] == "alpine:3.23.4"
    assert build["dockerfile_path"] == "upstream:docker-library/postgres/16/alpine/Dockerfile"
    assert len(build["layers"]) == len((EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines())
    assert len([layer for layer in build["layers"] if layer.get("digest")]) == 11
    source_inputs = {item["source_path"]: item for item in build["source_inputs"]}
    assert source_inputs["containers/db/init/01-schema.sql"]["destination_path"] == "/docker-entrypoint-initdb.d/01-schema.sql"
    assert db["os_version"] == "Alpine Linux v3.23"
    services = {(service["port"], service["protocol"], service["name"]) for service in db["services"]}
    assert (5432, "tcp", "postgres") in services

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert mounts["/var/lib/postgresql/data"]["source"] == "aptl_db_data"
    assert mounts["/var/lib/postgresql/data"]["source_kind"] == "volume"
    assert mounts["/docker-entrypoint-initdb.d"]["source"] == "containers/db/init"
    assert mounts["/docker-entrypoint-initdb.d"]["read_only"] is True

    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert len(filesystem) == len((EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines())
    assert filesystem["/docker-entrypoint-initdb.d/01-schema.sql"]["source_path"] == "containers/db/init/01-schema.sql"
    assert filesystem["/docker-entrypoint-initdb.d/01-schema.sql"]["provenance"] == "sha256:7a1748928d6222db2e3877ec8f6599ec7e1aec8c2956d2842b8e49e146c52981"
    assert filesystem["/var/lib/postgresql/data/postgresql.conf"]["owner_user"] == "postgres"
    assert filesystem["/var/lib/postgresql/data/pg_log/postgresql.log"]["stability"] == "log"

    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["health"]["status"] == "healthy"
    assert len(runtime["health"]["log"]) == 5
    assert "process" not in runtime, (
        "ACES PR #458 removed runtime.process; PID 1 identity now lives as "
        "processes[0]."
    )
    primary = runtime["processes"][0]
    assert primary["name"] == "postgres-postmaster"
    assert primary["pid"] == 1
    assert primary["role"] == "primary"
    assert primary["user"] == "postgres"
    assert "logging_collector=on" in " ".join(primary["command"])
    assert {process["name"] for process in runtime["processes"]} >= {"postgres-postmaster", "postgres-logger"}
    environment = {item["name"]: item for item in runtime["environment"]}
    assert environment["POSTGRES_PASSWORD"]["value"] == "techvault_db_pass"
    assert environment["POSTGRES_PASSWORD"]["value_classification"] == "secret_fixture"
    assert runtime["linux_capabilities"]["effective"] == []
    assert runtime["operational_policy"]["restart"] == "unless_stopped"
    limits = runtime["operational_policy"]["resource_limits"]
    assert limits["memory"] == 268435456
    assert limits["memory_swap"] == 536870912
    assert len(runtime["packages"]) == len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines())
    assert len(runtime["package_vulnerabilities"]) == len(_json_file("trivy-vulnerability-list.json"))
    database_service = runtime["database_services"][0]
    assert database_service["database_service_id"] == "techvault-postgres"
    assert database_service["service"] == "postgres"
    assert database_service["engine"] == "postgresql"
    assert database_service["protocol"] == "postgresql"
    assert database_service["version"] == "16.13"
    assert {listener["address"] for listener in database_service["listeners"]} == {
        "0.0.0.0",
        "::",
    }
    databases = {database["database_id"]: database for database in database_service["databases"]}
    assert set(databases) == {"postgres", "techvault", "template0", "template1"}
    assert databases["techvault"]["origin"] == "scenario"
    public_schema = databases["techvault"]["schemas"][0]
    assert public_schema["schema_id"] == "public"
    assert {table["name"] for table in public_schema["tables"]} == {
        "api_keys",
        "audit_log",
        "backup_config",
        "comments",
        "customers",
        "files",
        "sessions",
        "users",
    }
    roles = {role["role_id"]: role for role in database_service["roles"]}
    assert roles["techvault"]["role_type"] == "application"
    assert roles["techvault"]["can_login"] is True
    observed_roles = _postgres_role_rows()
    encoded_role_names = {role["name"]: role for role in database_service["roles"]}
    assert set(encoded_role_names) == set(observed_roles)
    for name, observed in observed_roles.items():
        assert encoded_role_names[name]["can_login"] == observed["can_login"]
    settings = {setting["name"]: setting for setting in database_service["settings"]}
    assert settings["listen_addresses"]["value"] == "*"
    assert settings["log_statement"]["value"] == "all"

    assert data["conditions"]["db-postgres-ready"]["command"] == "pg_isready -U techvault -d techvault"
    assert data["features"]["techvault-postgres-service"]["environment"][-1] == "POSTGRES_PASSWORD=techvault_db_pass"
    assert data["content"]["db-init-schema-sql"]["path"] == "/docker-entrypoint-initdb.d/01-schema.sql"
    assert data["relationships"]["db-logs-forwarded-wazuh"]["target"] == "wazuh-manager"
    assert data["relationships"]["webapp-connects-db"]["source"] == "nodes.webapp.runtime.applications.techvault-portal"
    assert data["relationships"]["webapp-connects-db"]["target"] == (
        "nodes.db.runtime.database_services.techvault-postgres.databases.techvault"
    )
    database_access = data["relationships"]["webapp-connects-db"]["database_access"]
    assert database_access["role_ref"] == "techvault"
    assert database_access["auth_method"] == "password"


def test_db_filesystem_tree_is_encoded_as_runtime_inventory():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    filesystem = {
        entry["path"]: entry
        for entry in data["nodes"]["db"]["runtime"]["filesystem_inventory"]
    }
    observed_paths = {
        line.split(maxsplit=6)[6]
        for line in (EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines()
    }
    assert observed_paths <= filesystem.keys()
    for digest_line in (EVIDENCE_DIR / "filesystem-checksums.txt").read_text(encoding="utf-8").splitlines():
        expected_digest, path = digest_line.split("  ", maxsplit=1)
        assert filesystem[path]["digest_algorithm"] == "sha256"
        assert filesystem[path]["content_digest"] == expected_digest


def test_db_runtime_local_identity_matches_passwd_and_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    local_identity = data["nodes"]["db"]["runtime"]["local_identity"]
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


def test_db_passwd_users_are_encoded_as_accounts():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    account_usernames = {
        account["username"]
        for name, account in data["accounts"].items()
        if name.startswith("db-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames <= account_usernames
    assert data["accounts"]["db-postgres-role-techvault"]["password_strength"] == "weak"


def test_techvault_sdl_db_uses_aces_pr458_and_460_forwarding_surfaces():
    """ACES PR #458 + #460 (#388 reconciliation): db's PostgreSQL-log forwarder
    is the off-node `wazuh-sidecar-db` container (ADR-020 carve-out;
    postgres:16-alpine has no first-party Wazuh package). #460 added the
    scenario-level `forwarding_agents:` registry so the sidecar can host the
    forwarder without mis-typing it as a node-hosted agent on db itself.
    """
    data = _yaml_file(TECHVAULT_SDL_PATH)

    scenario_agents = {
        agent["forwarding_agent_id"]: agent
        for agent in data.get("forwarding_agents", [])
    }
    assert "aptl-db-wazuh-agent" in scenario_agents, (
        "PR #460: db's off-node Wazuh sidecar must be registered under the "
        "scenario-level forwarding_agents registry, not under db's own "
        "runtime.forwarding_agents (which would mis-type where the agent runs)."
    )
    agent = scenario_agents["aptl-db-wazuh-agent"]
    assert agent["implementation"] == "wazuh_agent"
    assert agent["agent_kind"] == "log_forwarder"
    assert agent["name"] == "aptl-db-agent", (
        "Sidecar AGENT_NAME on compose service wazuh-sidecar-db is aptl-db-agent."
    )
    assert agent["buffer_policy"]["buffer_policy_id"] == "aptl-db-wazuh-agent-buffer"
    ship_target_nodes = {target["target_node_ref"] for target in agent["ship_targets"]}
    assert ship_target_nodes == {"wazuh-manager"}
    ship_target_ports = {target["ingestion_port"] for target in agent["ship_targets"]}
    assert ship_target_ports == {1514}

    db_runtime = data["nodes"]["db"]["runtime"]
    assert not db_runtime.get("forwarding_agents"), (
        "ADR-020: db itself runs no Wazuh daemons; its forwarder lives off-node "
        "on the wazuh-sidecar-db container, registered at scenario scope."
    )

    forward_rel = data["relationships"]["db-logs-forwarded-wazuh"]
    assert forward_rel["properties"] == {}, (
        "PR #458: the typed forwarding_edge payload replaces the legacy "
        "properties.protocol/source_log prose."
    )
    assert forward_rel["forwarding_edge"]["forwarder_ref"] == "aptl-db-wazuh-agent"


def test_db_runtime_network_matches_docker_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    network = data["nodes"]["db"]["runtime"]["network"]
    container = _json_file("docker-inspect.container.json")[0]
    docker_network = _json_file("docker-network.aptl-internal.json")[0]

    assert network["hostname"] == container["Config"]["Hostname"]
    assert network["domainname"] == container["Config"]["Domainname"]
    assert network["published_ports"] == []

    endpoint = network["endpoints"][0]
    observed = container["NetworkSettings"]["Networks"]["aptl_aptl-internal"]
    assert endpoint["network"] == "internal-net"
    assert endpoint["network_id"] == observed["NetworkID"] == docker_network["Id"]
    assert endpoint["endpoint_id"] == observed["EndpointID"]
    assert endpoint["ip_address"] == observed["IPAddress"] == "172.20.2.11"
    assert endpoint["ip_prefix_length"] == observed["IPPrefixLen"]
    assert endpoint["mac_address"] == observed["MacAddress"]
    assert endpoint["aliases"] == observed["Aliases"]
    assert endpoint["dns_names"] == observed["DNSNames"]
    assert endpoint["gateway"] == docker_network["IPAM"]["Config"][0]["Gateway"]
    assert endpoint["backend"]["driver"] == docker_network["Driver"]
    assert data["infrastructure"]["internal-net"]["properties"]["internal"] is True


def test_techvault_sdl_parses_and_compiles_with_db_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.techvault.db"].spec["node"]
    runtime = node["runtime"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["mounts"]) >= 20
    assert len(runtime["filesystem_inventory"]) == len((EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines())
    assert len(runtime["local_identity"]["users"]) == len(_runtime_baseline_section("users"))
    assert len(runtime["local_identity"]["groups"]) == len(_runtime_baseline_section("groups"))
    assert len(runtime["packages"]) == len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines())
    assert len(runtime["package_vulnerabilities"]) == 34
    database_service = runtime["database_services"][0]
    assert database_service["engine"] == "postgresql"
    assert database_service["protocol"] == "postgresql"
    assert {database["database_id"] for database in database_service["databases"]} == {
        "postgres",
        "techvault",
        "template0",
        "template1",
    }
    assert {role["role_id"] for role in database_service["roles"]} >= {"techvault"}
    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["health"]["status"] == "healthy"
    assert runtime["operational_policy"]["restart"] == "unless_stopped"


def test_parity_inventory_cites_db_inventory_and_aces_sdl():
    inventory = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in inventory["rows"]}

    assert rows["scen.techvault.db-inventory"]["legacy_source"] == "scenarios/techvault.sdl.yaml"
    assert rows["scen.techvault.db-inventory"]["category"] == "aces_sdl"
    assert rows["scen.techvault.db-inventory"]["blocking_followup"] == "n/a"
    assert "docs/aces/inventory/db/" in rows["scen.techvault.db-inventory"]["validation_evidence"]
    assert "Brad-Edwards/aces#388" in rows["scen.techvault.db-inventory"]["notes"]

    assert rows["compose.service.db"]["legacy_source"] == "docker-compose.yml (service: db)"
    assert rows["compose.service.db"]["category"] == "aces_sdl"
    assert rows["compose.service.db"]["blocking_followup"] == "n/a"
    assert "nodes.techvault.db" in rows["compose.service.db"]["aces_target"]
