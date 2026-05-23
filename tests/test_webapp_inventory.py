"""Checks for the SCN-010 webapp steady-state inventory bundle."""

from collections import Counter
from pathlib import Path
import hashlib
import json
import re

import pytest
import yaml

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_PATH = PROJECT_ROOT / "docs" / "aces" / "inventory" / "webapp-preflight.md"
WEBAPP_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "webapp"
WEBAPP_DOC_PATH = WEBAPP_DIR / "README.md"
LEDGER_PATH = WEBAPP_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = WEBAPP_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:7f2c715f953094ae36c10d15fbb038f0fdc6b855fd052236a95ad040410a25e0"
IMAGE_DIGEST = f"aptl-webapp@{IMAGE_ID}"
BUILD_HISTORY_LAYER_COUNT = 31
SOURCE_INPUT_COUNT = 18
LOCAL_IDENTITY_USER_COUNT = 23
LOCAL_IDENTITY_GROUP_COUNT = 45
FULL_RUNTIME_PACKAGE_COUNT = 223
FULL_TRIVY_FINDING_COUNT = 469
APPLICATION_ROUTE_COUNT = 19
WEBAPP_SCENARIO_WEAKNESSES = {
    "webapp-admin-authz-bypass",
    "webapp-api-rate-limit-missing",
    "webapp-backup-secret-disclosure",
    "webapp-command-injection",
    "webapp-debug-disclosure",
    "webapp-env-disclosure",
    "webapp-hardcoded-secret",
    "webapp-idor-files",
    "webapp-idor-users",
    "webapp-reflected-xss",
    "webapp-sqli-login",
    "webapp-sqli-search",
    "webapp-stored-xss",
    "webapp-unrestricted-upload",
    "webapp-upload-path-traversal",
    "webapp-verbose-error-disclosure",
    "webapp-weak-jwt",
}

REQUIRED_EVIDENCE_FILES = {
    "captured-at-utc.txt",
    "capture-limits.txt",
    "compose-service.webapp.json",
    "docker-compose-version.json",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-dmz.json",
    "docker-network.aptl-internal.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.webapp-logs.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "language-manifests.txt",
    "os-packages.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "trivy-version.txt",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}

SECRET_ENV_NAMES = (
    "APTL_FLAG_KEY",
    "DB_PASSWORD",
    "JWT_SECRET",
    "SECRET_KEY",
)
RUNTIME_SECRET_ENV_NAMES = ("DB_PASSWORD",)


def _json_file(name: str):
    with (EVIDENCE_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def _yaml_file(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def test_webapp_preflight_artifact_records_local_guardrails():
    text = PREFLIGHT_PATH.read_text(encoding="utf-8")
    required = (
        "gc_codex_architecture_preflight",
        "SCN-010 / issue #330",
        "docs/aces/inventory/webapp/",
        "scenarios/techvault.sdl.yaml",
        "ACES #354",
        "ACES expressivity gaps only",
        "The documentation carve-out does not apply",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Webapp preflight missing guardrails: {missing}"


def test_webapp_inventory_note_declares_scope_and_evidence():
    text = WEBAPP_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #330",
        "aptl-webapp",
        "custom-build",
        "already-running local lab",
        "not run `aptl lab stop -v && aptl lab start`",
        "Docker Compose service",
        "in-process Wazuh agent",
        "CAP_NET_ADMIN",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "ACES #354",
        "ACES #358",
        "ACES #363",
        "ACES #364",
        "ACES #365",
        "ACES #366",
        "ACES #367",
        "ACES #368",
        "Full root filesystem cataloguing is not blocked",
        "by ACES expressivity",
        "not proof that a destructive",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Webapp inventory note missing scope markers: {missing}"


def test_webapp_mapping_ledger_validates_and_tracks_gap_handoff():
    result = validate_mapping_ledger(WEBAPP_DIR)
    assert result.ok, result.errors
    assert result.fact_count == 23
    assert result.encoded_count == 23
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    assert len(ledger["correspondence_checks"]) == 2
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["webapp.build.recipe"] == "encoded"
    assert dispositions["webapp.runtime.log-volume"] == "encoded"
    assert dispositions["webapp.runtime.mount-table"] == "encoded"
    assert dispositions["webapp.runtime.filesystem-content"] == "encoded"
    assert dispositions["webapp.runtime.filesystem-metadata"] == "encoded"
    assert dispositions["webapp.runtime.local-accounts"] == "encoded_with_caveat"
    assert dispositions["webapp.runtime.local-identity-database"] == "encoded"
    assert dispositions["webapp.network.realization-metadata"] == "encoded"
    assert dispositions["webapp.application.http-surface"] == "encoded"
    assert dispositions["webapp.runtime.container-host-config"] == "encoded"
    assert dispositions["webapp.runtime.supervised-process-set"] == "encoded"
    assert dispositions["webapp.runtime.environment-policy"] == "encoded"
    assert dispositions["webapp.runtime.capability-restart-policy"] == "encoded"


def test_webapp_gap_report_surfaces_remaining_aces_gaps_only():
    report = gap_report(WEBAPP_DIR)
    gaps = {gap["fact_id"]: gap for gap in report["gaps"]}
    assert set(gaps) == set()
    assert not report["triage_needed"]


def test_webapp_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_webapp_evidence_sha256_manifest_matches_files():
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


def test_webapp_evidence_does_not_contain_raw_secret_assignments():
    raw_secret_assignment = re.compile(
        rf"^({'|'.join(re.escape(name) for name in SECRET_ENV_NAMES)})=(?!<REDACTED-).+",
        re.MULTILINE,
    )
    offenders = {}
    for path in EVIDENCE_DIR.iterdir():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        leaked = sorted(
            {match.group(1) for match in raw_secret_assignment.finditer(text)}
        )
        if leaked:
            offenders[path.name] = leaked
    assert not offenders, f"Raw secret assignments leaked into evidence: {offenders}"


def test_webapp_container_runtime_state_and_redaction_boundary():
    container = _json_file("docker-inspect.container.json")[0]
    env = container["Config"]["Env"]
    joined_env = "\n".join(env)

    assert container["Name"] == "/aptl-webapp"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "webapp"
    assert container["HostConfig"]["Memory"] == 536870912
    assert container["HostConfig"]["CapAdd"] == ["CAP_NET_ADMIN"]
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert "aptl_webapp_logs:/var/log/gunicorn:rw" in container["HostConfig"]["Binds"]
    assert (
        container["NetworkSettings"]["Networks"]["aptl_aptl-dmz"]["IPAddress"]
        == "172.20.1.20"
    )
    assert (
        container["NetworkSettings"]["Networks"]["aptl_aptl-internal"]["IPAddress"]
        == "172.20.2.25"
    )
    for name in RUNTIME_SECRET_ENV_NAMES:
        assert re.search(rf"^{name}=<REDACTED-[A-Z0-9-]+>$", joined_env, re.MULTILINE)


def test_webapp_image_identity_and_source_package_are_recorded():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["WorkingDir"] == "/app"
    assert image["Config"]["Entrypoint"] == ["/entrypoint.sh"]
    assert "8080/tcp" in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 20

    source_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(
        encoding="utf-8"
    )
    for source_path in (
        "containers/webapp/Dockerfile",
        "containers/webapp/entrypoint.sh",
        "containers/webapp/supervisord.conf",
        "containers/webapp/requirements.txt",
        "containers/webapp/app/app.py",
    ):
        assert source_path in source_checksums


def test_webapp_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        'VERSION="13 (trixie)"',
        "uid=0(root)",
        "/app",
        "0.0.0.0:8080",
        "/usr/bin/supervisord",
        "/usr/local/bin/gunicorn",
        "/usr/sbin/rsyslogd",
        "/opt/aptl/wazuh/wazuh-agent.sh",
        "/var/log/gunicorn",
        "CapEff:",
        "gunicorn                         RUNNING",
        "wazuh-agent                      RUNNING",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_webapp_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)

    assert counts == dict(computed)
    assert sum(counts.values()) == len(vulnerabilities)
    assert vulnerabilities
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)


def test_techvault_sdl_encodes_webapp_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    webapp = data["nodes"]["webapp"]
    runtime = webapp["runtime"]
    build = webapp["source"]["build"]

    assert data["name"] == "techvault"
    assert webapp["source"]["name"] == "aptl-webapp"
    assert webapp["source"]["version"] == IMAGE_DIGEST
    assert build["base_image"] == "python:3.11-slim"
    assert build["dockerfile_path"] == "containers/webapp/Dockerfile"
    assert len(build["instructions"]) == 22
    assert len(build["layers"]) == BUILD_HISTORY_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert len(build["copied_sources"]) == 9
    assert build["config"]["entrypoint"] == ["/entrypoint.sh"]
    assert build["config"]["command"] == []
    assert build["config"]["working_directory"] == "/app"
    assert "8080/tcp" in build["config"]["exposed_ports"]
    assert build["attestation"]["status"] == "absent"
    assert build["attestation"]["verification"] == "not_applicable"
    build_sources = {item["source_path"]: item for item in build["source_inputs"]}
    assert build_sources["containers/webapp/app/app.py"]["destination_path"] == (
        "/app/app.py"
    )
    assert build_sources["containers/webapp/app/app.py"]["checksum"] == (
        "08beb9eec94aee668f19dc3d9302e465031ded519342205d1f1421d55b0814d6"
    )
    rootfs_layer_digests = {
        layer["digest"] for layer in build["layers"] if layer.get("digest")
    }
    assert len(rootfs_layer_digests) == 20
    assert (
        "sha256:79dd1f4c855cd061f687a994426634cf5f84c8ecdbc66c7a7d118e828dd93c99"
        in (rootfs_layer_digests)
    )
    assert (
        "sha256:622338701f7b3204a528003eb94e09d1f2e38f584835a6658b266a0f87ba8a91"
        in (rootfs_layer_digests)
    )
    assert webapp["os"] == "linux"
    assert webapp["os_version"] == "Debian GNU/Linux 13 (trixie)"
    assert {"port": 8080, "protocol": "tcp", "name": "http"} in webapp["services"]
    assert set(webapp["vulnerabilities"]) == WEBAPP_SCENARIO_WEAKNESSES
    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert len(mounts) == 26
    assert mounts["/var/log/gunicorn"]["source"] == "aptl_webapp_logs"
    assert mounts["/var/log/gunicorn"]["source_kind"] == "volume"
    assert mounts["/var/log/gunicorn"]["filesystem_type"] == "ext4"
    assert mounts["/var/log/gunicorn"]["stability"] == "volume_backed"
    assert mounts["/sys"]["read_only"] is True
    assert mounts["/sys"]["filesystem_type"] == "sysfs"
    assert mounts["/"]["backend_generated"] is True
    assert any(option.startswith("lowerdir=") for option in mounts["/"]["options"])
    assert "nsdelegate" in mounts["/sys/fs/cgroup"]["options"]
    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert len(filesystem) == 24
    assert filesystem["/app/app.py"]["content_digest"] == (
        "08beb9eec94aee668f19dc3d9302e465031ded519342205d1f1421d55b0814d6"
    )
    assert filesystem["/app/app.py"]["mode"] == "0644"
    assert filesystem["/app/user.txt"]["sensitivity"] == "secret_fixture"
    assert filesystem["/app/user.txt"]["stability"] == "generated"
    assert filesystem["/var/ossec/etc/ossec.conf"]["owner_group"] == "wazuh"
    assert filesystem["/var/ossec/etc/ossec.conf"]["gid"] == 102
    assert filesystem["/entrypoint.sh"]["mode"] == "0775"
    assert filesystem["/app"]["entry_type"] == "directory"
    container_config = runtime["container"]
    assert container_config["entrypoint"] == ["/entrypoint.sh"]
    assert container_config["log_driver"] == "json-file"
    assert container_config["namespaces"] == {
        "cgroup": "private",
        "ipc": "private",
        "pid": "",
        "userns": "",
        "uts": "",
    }
    assert container_config["privileged"] is False
    assert container_config["read_only_rootfs"] is False
    assert container_config["publish_all_ports"] is False
    assert container_config["autoremove"] is False
    assert container_config["shm_size"] == 67108864
    assert "/proc/kcore" in container_config["masked_paths"]
    assert "/proc/sys" in container_config["read_only_paths"]
    assert container_config["runtime_name"] == "runc"
    assert runtime["health"]["status"] == "healthy"
    assert runtime["health"]["failing_streak"] == 0
    assert len(runtime["health"]["log"]) == 5
    assert "TechVault Solutions" in runtime["health"]["log"][0]["output"]
    assert runtime["process"]["command"] == [
        "/usr/bin/python3",
        "/usr/bin/supervisord",
        "-n",
        "-c",
        "/etc/supervisor/supervisord.conf",
    ]
    process_names = {process["name"] for process in runtime["processes"]}
    assert {
        "supervisord",
        "gunicorn-master",
        "gunicorn-worker-1",
        "gunicorn-worker-2",
        "rsyslogd",
        "wazuh-agent-wrapper",
        "wazuh-execd",
        "wazuh-agentd",
        "wazuh-syscheckd",
        "wazuh-logcollector",
        "wazuh-modulesd",
    } <= process_names
    environment = {item["name"]: item for item in runtime["environment"]}
    assert environment["DB_PASSWORD"]["value"] == "techvault_db_pass"
    assert environment["DB_PASSWORD"]["value_classification"] == "secret_fixture"
    assert environment["WAZUH_MANAGER"]["value"] == "wazuh.manager"
    assert environment["PYTHON_VERSION"]["provenance"] == "image"
    assert runtime["linux_capabilities"]["required"] == ["CAP_NET_ADMIN"]
    assert "CAP_NET_ADMIN" in runtime["linux_capabilities"]["effective"]
    assert runtime["operational_policy"]["restart"] == "unless_stopped"
    assert runtime["operational_policy"]["resource_limits"] == {
        "memory": 536870912,
        "memory_swap": 1073741824,
    }
    network = runtime["network"]
    assert network["hostname"] == "webapp"
    assert network["domainname"] == ""
    assert len(network["endpoints"]) == 2
    endpoints = {endpoint["network"]: endpoint for endpoint in network["endpoints"]}
    dmz_endpoint = endpoints["dmz-net"]
    assert dmz_endpoint["network_id"] == (
        "da8da844dbb2e771c0d77dd3a0a33392b53ef0547f5cab073acf3d7c8136b06b"
    )
    assert dmz_endpoint["network_id_stability"] == "stable"
    assert dmz_endpoint["endpoint_id"] == (
        "601208e50783a00e3124c4c0797dfde773f89aeaf159b67791b1057f691be5e0"
    )
    assert dmz_endpoint["endpoint_id_stability"] == "ephemeral"
    assert dmz_endpoint["backend_generated"] is True
    assert dmz_endpoint["ip_address"] == "172.20.1.20"
    assert dmz_endpoint["ip_prefix_length"] == 24
    assert dmz_endpoint["gateway"] == "172.20.1.1"
    assert dmz_endpoint["mac_address"] == "ea:76:a0:d9:0f:2c"
    assert dmz_endpoint["aliases"] == ["aptl-webapp", "webapp"]
    assert dmz_endpoint["dns_names"] == ["aptl-webapp", "webapp", "dfcf66bdcb7b"]
    assert dmz_endpoint["generated_dns_names"] == ["dfcf66bdcb7b"]
    assert dmz_endpoint["backend"]["driver"] == "bridge"
    assert dmz_endpoint["backend"]["ipam_driver"] == "default"
    assert dmz_endpoint["backend"]["driver_options"] == {}
    assert dmz_endpoint["backend"]["ipam_options"] == {}

    internal_endpoint = endpoints["internal-net"]
    assert internal_endpoint["network_id"] == (
        "13398d126254b7592401f00b79f8e80a4ff32fe680b7b3f999028fb6dbe8fb20"
    )
    assert internal_endpoint["network_id_stability"] == "stable"
    assert internal_endpoint["endpoint_id"] == (
        "56ce35d9af612ec7a488a076b079cea14359481498f3fdd1826ae34b689dd5e8"
    )
    assert internal_endpoint["endpoint_id_stability"] == "ephemeral"
    assert internal_endpoint["backend_generated"] is True
    assert internal_endpoint["ip_address"] == "172.20.2.25"
    assert internal_endpoint["ip_prefix_length"] == 24
    assert internal_endpoint["gateway"] == "172.20.2.1"
    assert internal_endpoint["mac_address"] == "42:7a:3e:d1:8c:ed"
    assert internal_endpoint["aliases"] == ["aptl-webapp", "webapp"]
    assert internal_endpoint["dns_names"] == [
        "aptl-webapp",
        "webapp",
        "dfcf66bdcb7b",
    ]
    assert internal_endpoint["generated_dns_names"] == ["dfcf66bdcb7b"]
    assert internal_endpoint["backend"]["driver"] == "bridge"
    assert internal_endpoint["backend"]["ipam_driver"] == "default"
    assert internal_endpoint["backend"]["driver_options"] == {}
    assert internal_endpoint["backend"]["ipam_options"] == {}
    assert network["published_ports"] == [
        {
            "container_port": 8080,
            "protocol": "tcp",
            "host_ip": "",
            "host_port": 8080,
            "description": (
                "Docker HostConfig publishes 8080/tcp to host port 8080 with "
                "an empty HostIp, meaning all host interfaces for this capture."
            ),
        }
    ]
    applications = runtime["applications"]
    assert len(applications) == 1
    application = applications[0]
    assert application["application_id"] == "techvault-portal"
    assert application["service"] == "http"
    assert application["protocol"] == "http"
    assert application["framework"] == "Flask 3.1.0"
    assert application["base_path"] == "/"
    routes = {route["route_id"]: route for route in application["routes"]}
    assert len(routes) == APPLICATION_ROUTE_COUNT
    assert {route["path"] for route in routes.values()} >= {
        "/",
        "/login",
        "/logout",
        "/dashboard",
        "/admin",
        "/upload",
        "/api/v1/files/<int:file_id>",
        "/api/v1/users/<int:user_id>",
        "/api/v1/customers",
        "/api/v1/token",
        "/tools/ping",
        "/search",
        "/comment",
        "/debug",
        "/robots.txt",
        "/.env",
        "/static/<path:filename>",
        "/<unmatched_path>",
        "/<erroring_path>",
    }
    login_route = routes["webapp-login"]
    assert login_route["methods"] == ["GET", "HEAD", "OPTIONS", "POST"]
    assert {
        param["name"]: param["location"] for param in login_route["parameters"]
    } == {
        "username": "form",
        "password": "form",
    }
    assert {response["status_code"] for response in login_route["responses"]} == {
        200,
        401,
        500,
    }
    assert login_route["templates"] == [
        "/app/templates/login.html",
        "/app/templates/base.html",
    ]
    assert login_route["static_assets"] == ["/app/static/style.css"]
    assert set(login_route["vulnerability_refs"]) == {
        "webapp-sqli-login",
        "webapp-verbose-error-disclosure",
    }

    admin_route = routes["webapp-admin"]
    assert admin_route["auth_required"] is True
    assert admin_route["session_required"] is True
    assert set(admin_route["vulnerability_refs"]) == {
        "webapp-admin-authz-bypass",
        "webapp-backup-secret-disclosure",
    }
    admin_fields = {field["name"]: field for field in admin_route["exposed_fields"]}
    assert admin_fields["backup_config.secret_key"]["sensitivity"] == "secret_fixture"

    env_route = routes["webapp-env"]
    env_fields = {field["name"]: field for field in env_route["exposed_fields"]}
    assert env_fields["DB_PASSWORD"]["value"] == "techvault_db_pass"
    assert env_fields["DB_PASSWORD"]["sensitivity"] == "secret_fixture"
    assert env_fields["SECRET_KEY"]["value"] == "techvault-secret-key-2024"
    assert env_fields["JWT_SECRET"]["value"] == "techvault-jwt-weak"
    assert set(env_route["vulnerability_refs"]) == {
        "webapp-env-disclosure",
        "webapp-hardcoded-secret",
        "webapp-weak-jwt",
    }

    debug_route = routes["webapp-debug"]
    debug_fields = {field["name"]: field for field in debug_route["exposed_fields"]}
    assert debug_fields["framework"]["value"] == "Flask 3.1.0"
    assert debug_fields["secret_key_length"]["value"] == "25"
    assert debug_fields["jwt_algorithm"]["value"] == "HS256"
    assert debug_route["vulnerability_refs"] == ["webapp-debug-disclosure"]

    assert routes["webapp-static-style"]["static_assets"] == ["/app/static/style.css"]
    assert routes["webapp-error-404"]["responses"][0]["status_code"] == 404
    assert routes["webapp-error-500"]["vulnerability_refs"] == [
        "webapp-verbose-error-disclosure"
    ]
    package_names = {package["name"] for package in runtime["packages"]}
    assert len(runtime["packages"]) == FULL_RUNTIME_PACKAGE_COUNT
    assert {"python3", "supervisor", "curl", "iptables", "Jinja2"} <= package_names
    manifest_paths = {manifest["path"] for manifest in runtime["dependency_manifests"]}
    assert "/app/requirements.txt" in manifest_paths
    assert len(runtime["package_vulnerabilities"]) == FULL_TRIVY_FINDING_COUNT
    assert {item["severity"] for item in runtime["package_vulnerabilities"]} == {
        "critical",
        "high",
        "medium",
        "low",
    }

    infrastructure = data["infrastructure"]
    assert infrastructure["webapp"]["links"] == ["dmz-net", "internal-net"]
    assert infrastructure["webapp"]["properties"] == [
        {"dmz-net": "172.20.1.20"},
        {"internal-net": "172.20.2.25"},
    ]
    assert infrastructure["webapp"]["dependencies"] == ["db", "wazuh-manager"]

    content = data["content"]
    assert len([name for name in content if name.startswith("webapp-")]) == 24
    assert content["webapp-file-app-app-py"]["path"] == "/app/app.py"
    assert content["webapp-file-app-app-py"]["source"] == {
        "name": "containers/webapp/app/app.py",
        "version": "sha256:08beb9eec94aee668f19dc3d9302e465031ded519342205d1f1421d55b0814d6",
    }
    assert content["webapp-file-app-user-txt"]["sensitive"] is True
    assert content["webapp-dir-opt-aptl-wazuh"]["destination"] == "/opt/aptl/wazuh"

    accounts = data["accounts"]
    assert len([name for name in accounts if name.startswith("webapp-local-")]) == 23
    assert accounts["webapp-local-root"]["shell"] == "/bin/bash"
    assert accounts["webapp-local-wazuh"]["home"] == "/var/ossec"
    assert accounts["webapp-local-wazuh"]["disabled"] is True
    local_identity = runtime["local_identity"]
    assert len(local_identity["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(local_identity["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert local_identity["sudo_rules"] == []
    local_users = {user["username"]: user for user in local_identity["users"]}
    assert local_users["root"]["uid"] == 0
    assert local_users["root"]["primary_gid"] == 0
    assert local_users["root"]["primary_group"] == "root"
    assert local_users["root"]["gecos"] == "root"
    assert local_users["root"]["shell"] == "/bin/bash"
    assert local_users["wazuh"]["uid"] == 101
    assert local_users["wazuh"]["primary_gid"] == 102
    assert local_users["wazuh"]["primary_group"] == "wazuh"
    assert local_users["wazuh"]["home"] == "/var/ossec"
    assert local_users["wazuh"]["shell"] == "/sbin/nologin"
    assert local_users["wazuh"]["no_login"] is True
    local_groups = {group["name"]: group for group in local_identity["groups"]}
    assert local_groups["wazuh"] == {
        "name": "wazuh",
        "gid": 102,
        "members": [],
        "provenance": "package",
    }
    assert local_groups["sudo"]["gid"] == 27


def test_webapp_filesystem_checksum_paths_are_encoded_as_content():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content_paths = {
        item["path"] for item in data["content"].values() if item["type"] == "File"
    }
    checksum_paths = {
        line.split("  ", maxsplit=1)[1]
        for line in (EVIDENCE_DIR / "filesystem-checksums.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    }
    assert checksum_paths <= content_paths


def test_webapp_filesystem_tree_is_encoded_as_runtime_inventory():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    filesystem = {
        entry["path"]: entry
        for entry in data["nodes"]["webapp"]["runtime"]["filesystem_inventory"]
    }
    observed_paths = {
        line.split(maxsplit=4)[4]
        for line in (EVIDENCE_DIR / "filesystem-tree.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    }
    assert observed_paths <= filesystem.keys()
    for digest_line in (
        (EVIDENCE_DIR / "filesystem-checksums.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        expected_digest, path = digest_line.split("  ", maxsplit=1)
        assert filesystem[path]["digest_algorithm"] == "sha256"
        assert filesystem[path]["content_digest"] == expected_digest


def test_webapp_passwd_users_are_encoded_as_accounts():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    account_usernames = {
        account["username"]
        for name, account in data["accounts"].items()
        if name.startswith("webapp-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames <= account_usernames


def test_webapp_runtime_local_identity_matches_passwd_and_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    local_identity = data["nodes"]["webapp"]["runtime"]["local_identity"]
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


def test_webapp_runtime_network_matches_docker_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    network = data["nodes"]["webapp"]["runtime"]["network"]
    container = _json_file("docker-inspect.container.json")[0]
    docker_networks = {
        "dmz-net": ("aptl_aptl-dmz", _json_file("docker-network.aptl-dmz.json")[0]),
        "internal-net": (
            "aptl_aptl-internal",
            _json_file("docker-network.aptl-internal.json")[0],
        ),
    }

    assert network["hostname"] == container["Config"]["Hostname"]
    assert network["domainname"] == container["Config"]["Domainname"]

    endpoints = {endpoint["network"]: endpoint for endpoint in network["endpoints"]}
    for sdl_network, (docker_name, docker_network) in docker_networks.items():
        observed = container["NetworkSettings"]["Networks"][docker_name]
        endpoint = endpoints[sdl_network]
        assert endpoint["network_id"] == observed["NetworkID"] == docker_network["Id"]
        assert endpoint["endpoint_id"] == observed["EndpointID"]
        assert endpoint["ip_address"] == observed["IPAddress"]
        assert endpoint["ip_prefix_length"] == observed["IPPrefixLen"]
        assert endpoint["mac_address"] == observed["MacAddress"]
        assert endpoint["aliases"] == observed["Aliases"]
        assert endpoint["dns_names"] == observed["DNSNames"]
        assert endpoint["generated_dns_names"] == ["dfcf66bdcb7b"]
        assert endpoint["gateway"] == docker_network["IPAM"]["Config"][0]["Gateway"]
        assert endpoint["backend"]["driver"] == docker_network["Driver"]
        assert endpoint["backend"]["ipam_driver"] == docker_network["IPAM"]["Driver"]
        assert endpoint["backend"]["driver_options"] == docker_network["Options"]
        assert endpoint["backend"]["ipam_options"] == {}

    published = network["published_ports"]
    assert len(published) == 1
    binding = published[0]
    host_binding = container["HostConfig"]["PortBindings"]["8080/tcp"][0]
    assert binding["container_port"] == 8080
    assert binding["protocol"] == "tcp"
    assert binding["host_ip"] == host_binding["HostIp"]
    assert binding["host_port"] == int(host_binding["HostPort"])


def test_webapp_runtime_application_surface_matches_flask_source():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    routes = {
        route["route_id"]: route
        for route in data["nodes"]["webapp"]["runtime"]["applications"][0]["routes"]
    }
    source = (PROJECT_ROOT / "containers" / "webapp" / "app" / "app.py").read_text(
        encoding="utf-8"
    )

    source_route_paths = set(re.findall(r'@app\.route\("([^"]+)"', source))
    encoded_paths = {route["path"] for route in routes.values()}
    assert source_route_paths <= encoded_paths
    assert "/static/<path:filename>" in encoded_paths
    assert "/<unmatched_path>" in encoded_paths
    assert "/<erroring_path>" in encoded_paths
    assert "@app.errorhandler(404)" in source
    assert "@app.errorhandler(500)" in source

    explicit_method_expectations = {
        "webapp-login": {"GET", "POST"},
        "webapp-upload": {"GET", "POST"},
        "webapp-api-token": {"POST"},
        "webapp-tools-ping": {"GET", "POST"},
        "webapp-comment": {"POST"},
    }
    for route_id, expected_methods in explicit_method_expectations.items():
        assert expected_methods <= set(routes[route_id]["methods"])

    parameter_expectations = {
        "webapp-login": {"username", "password"},
        "webapp-upload": {"file"},
        "webapp-api-file": {"file_id", "X-API-Key", "api_key", "session"},
        "webapp-api-user": {"user_id"},
        "webapp-api-customers": {"search", "X-API-Key", "api_key", "session"},
        "webapp-api-token": {"username", "password"},
        "webapp-tools-ping": {"host", "session"},
        "webapp-search": {"q", "session"},
        "webapp-comment": {"content", "page", "session"},
    }
    for route_id, expected_parameters in parameter_expectations.items():
        encoded_parameters = {param["name"] for param in routes[route_id]["parameters"]}
        assert expected_parameters <= encoded_parameters

    template_names = set(re.findall(r'render_template\("([^"]+)"', source))
    encoded_templates = {
        Path(template).name
        for route in routes.values()
        for template in route.get("templates", [])
    }
    assert template_names <= encoded_templates

    vulnerability_refs = {
        ref for route in routes.values() for ref in route.get("vulnerability_refs", [])
    }
    assert vulnerability_refs <= set(data["vulnerabilities"])
    assert {
        "webapp-admin-authz-bypass",
        "webapp-backup-secret-disclosure",
        "webapp-upload-path-traversal",
        "webapp-api-rate-limit-missing",
        "webapp-verbose-error-disclosure",
    } <= vulnerability_refs


def test_webapp_runtime_mount_targets_are_encoded():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    mount_targets = {
        mount["target"] for mount in data["nodes"]["webapp"]["runtime"]["mounts"]
    }
    observed_targets = set()
    for line in _runtime_baseline_section("mounts"):
        match = re.match(r".+? on (\S+) type \S+ \(", line)
        if match:
            observed_targets.add(match.group(1))
    assert observed_targets <= mount_targets


def test_techvault_sdl_parses_and_compiles_with_aces_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.webapp"].spec["node"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert len(build["instructions"]) == 22
    assert len(build["layers"]) == BUILD_HISTORY_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert build["attestation"]["status"] == "absent"
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert runtime["local_identity"]["sudo_rules"] == []
    assert len(runtime["mounts"]) == 26
    assert len(runtime["filesystem_inventory"]) == 24
    assert len(runtime["network"]["endpoints"]) == 2
    assert len(runtime["network"]["published_ports"]) == 1
    assert len(runtime["applications"]) == 1
    assert len(runtime["applications"][0]["routes"]) == APPLICATION_ROUTE_COUNT
    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["health"]["status"] == "healthy"
    assert len(runtime["health"]["log"]) == 5
    assert len(runtime["processes"]) == 11
    assert len(runtime["environment"]) == 21
    assert len(runtime["packages"]) == FULL_RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == FULL_TRIVY_FINDING_COUNT
    assert runtime["linux_capabilities"]["add"] == ["CAP_NET_ADMIN"]
    assert runtime["operational_policy"]["restart"] == "unless_stopped"


def test_parity_inventory_cites_webapp_inventory_and_aces_sdl():
    inventory = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in inventory["rows"]}

    assert rows["scen.techvault.webapp-inventory"]["legacy_source"] == (
        "scenarios/techvault.sdl.yaml"
    )
    assert rows["scen.techvault.webapp-inventory"]["category"] == "aces_sdl"
    assert rows["scen.techvault.webapp-inventory"]["blocking_followup"] == "n/a"
    assert (
        "Brad-Edwards/aces#364"
        not in rows["scen.techvault.webapp-inventory"]["blocking_followup"]
    )
    assert (
        "Brad-Edwards/aces#365"
        not in rows["scen.techvault.webapp-inventory"]["blocking_followup"]
    )
    assert (
        "Brad-Edwards/aces#366"
        not in rows["scen.techvault.webapp-inventory"]["blocking_followup"]
    )
    assert (
        "Brad-Edwards/aces#367"
        not in rows["scen.techvault.webapp-inventory"]["blocking_followup"]
    )
    assert (
        "ACES #363/#364/#365/#366/#367/#368 consumed"
        in rows["scen.techvault.webapp-inventory"]["validation_evidence"]
    )
    assert (
        "Brad-Edwards/aces#363"
        not in rows["scen.techvault.webapp-inventory"]["blocking_followup"]
    )
    assert (
        "Brad-Edwards/aces#368"
        not in rows["scen.techvault.webapp-inventory"]["blocking_followup"]
    )
    assert (
        "docs/aces/inventory/webapp/"
        in rows["scen.techvault.webapp-inventory"]["validation_evidence"]
    )

    assert rows["compose.service.webapp"]["legacy_source"] == (
        "docker-compose.yml (service: webapp)"
    )
    assert rows["compose.service.webapp"]["category"] == "aces_sdl"
    assert "nodes.webapp" in rows["compose.service.webapp"]["aces_target"]
