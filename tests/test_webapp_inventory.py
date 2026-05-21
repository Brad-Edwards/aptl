"""Checks for the SCN-010 webapp steady-state inventory bundle."""

from collections import Counter
from pathlib import Path
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
PREFLIGHT_PATH = PROJECT_ROOT / "docs" / "aces" / "inventory" / "webapp-preflight.md"
WEBAPP_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "webapp"
WEBAPP_DOC_PATH = WEBAPP_DIR / "README.md"
LEDGER_PATH = WEBAPP_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = WEBAPP_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:7f2c715f953094ae36c10d15fbb038f0fdc6b855fd052236a95ad040410a25e0"
IMAGE_DIGEST = f"aptl-webapp@{IMAGE_ID}"
ACES_IDENTITY_GAP = 365
ACES_NETWORK_GAP = 366
ACES_HTTP_SURFACE_GAP = 367
BUILD_HISTORY_LAYER_COUNT = 31
SOURCE_INPUT_COUNT = 18
FULL_RUNTIME_PACKAGE_COUNT = 223
FULL_TRIVY_FINDING_COUNT = 469

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
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Webapp inventory note missing scope markers: {missing}"


def test_webapp_mapping_ledger_validates_and_tracks_gap_handoff():
    result = validate_mapping_ledger(WEBAPP_DIR)
    assert result.ok, result.errors
    assert result.fact_count == 23
    assert result.encoded_count == 20
    assert result.blocked_count == 3
    assert result.triage_count == 0
    assert result.gap_issues == [
        f"ACES #{ACES_IDENTITY_GAP}",
        f"ACES #{ACES_NETWORK_GAP}",
        f"ACES #{ACES_HTTP_SURFACE_GAP}",
    ]

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
    assert dispositions["webapp.runtime.local-identity-database"] == "blocked_by_aces_gap"
    assert dispositions["webapp.network.realization-metadata"] == "blocked_by_aces_gap"
    assert dispositions["webapp.application.http-surface"] == "blocked_by_aces_gap"
    assert dispositions["webapp.runtime.container-host-config"] == "encoded"
    assert dispositions["webapp.runtime.supervised-process-set"] == "encoded"
    assert dispositions["webapp.runtime.environment-policy"] == "encoded"
    assert dispositions["webapp.runtime.capability-restart-policy"] == "encoded"


def test_webapp_gap_report_surfaces_remaining_aces_gaps_only():
    report = gap_report(WEBAPP_DIR)
    gaps = {gap["fact_id"]: gap for gap in report["gaps"]}
    assert set(gaps) == {
        "webapp.runtime.local-identity-database",
        "webapp.network.realization-metadata",
        "webapp.application.http-surface",
    }
    assert not report["triage_needed"]
    assert gaps["webapp.runtime.local-identity-database"]["gap_issue"]["number"] == (
        ACES_IDENTITY_GAP
    )
    assert gaps["webapp.network.realization-metadata"]["gap_issue"]["number"] == (
        ACES_NETWORK_GAP
    )
    assert gaps["webapp.application.http-surface"]["gap_issue"]["number"] == (
        ACES_HTTP_SURFACE_GAP
    )


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
    assert "sha256:79dd1f4c855cd061f687a994426634cf5f84c8ecdbc66c7a7d118e828dd93c99" in (
        rootfs_layer_digests
    )
    assert "sha256:622338701f7b3204a528003eb94e09d1f2e38f584835a6658b266a0f87ba8a91" in (
        rootfs_layer_digests
    )
    assert webapp["os"] == "linux"
    assert webapp["os_version"] == "Debian GNU/Linux 13 (trixie)"
    assert {"port": 8080, "protocol": "tcp", "name": "http"} in webapp["services"]
    assert "webapp-sqli-login" in webapp["vulnerabilities"]
    assert "webapp-command-injection" in webapp["vulnerabilities"]
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
    package_names = {package["name"] for package in runtime["packages"]}
    assert len(runtime["packages"]) == FULL_RUNTIME_PACKAGE_COUNT
    assert {"python3", "supervisor", "curl", "iptables", "Jinja2"} <= package_names
    manifest_paths = {manifest["path"] for manifest in runtime["dependency_manifests"]}
    assert "/app/requirements.txt" in manifest_paths
    assert len(runtime["package_vulnerabilities"]) == FULL_TRIVY_FINDING_COUNT
    assert {
        item["severity"] for item in runtime["package_vulnerabilities"]
    } == {"critical", "high", "medium", "low"}

    infrastructure = data["infrastructure"]
    assert infrastructure["webapp"]["links"] == ["dmz-net", "internal-net"]
    assert infrastructure["webapp"]["properties"] == [
        {"dmz-net": "172.20.1.20"},
        {"internal-net": "172.20.2.25"},
    ]
    assert infrastructure["webapp"]["dependencies"] == ["db", "wazuh-manager"]

    content = data["content"]
    assert len(content) == 24
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


def test_webapp_filesystem_checksum_paths_are_encoded_as_content():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content_paths = {
        item["path"]
        for item in data["content"].values()
        if item["type"] == "File"
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
    for digest_line in (EVIDENCE_DIR / "filesystem-checksums.txt").read_text(
        encoding="utf-8"
    ).splitlines():
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


def test_webapp_runtime_mount_targets_are_encoded():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    mount_targets = {mount["target"] for mount in data["nodes"]["webapp"]["runtime"]["mounts"]}
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
    assert len(runtime["mounts"]) == 26
    assert len(runtime["filesystem_inventory"]) == 24
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
    assert rows["scen.techvault.webapp-inventory"]["category"] == (
        "aces_schema_profile_gap"
    )
    assert "Brad-Edwards/aces#364" not in rows["scen.techvault.webapp-inventory"][
        "blocking_followup"
    ]
    assert "ACES #363/#364/#368 consumed" in rows["scen.techvault.webapp-inventory"][
        "validation_evidence"
    ]
    assert "Brad-Edwards/aces#363" not in rows["scen.techvault.webapp-inventory"][
        "blocking_followup"
    ]
    assert "Brad-Edwards/aces#368" not in rows["scen.techvault.webapp-inventory"][
        "blocking_followup"
    ]
    assert "docs/aces/inventory/webapp/" in rows["scen.techvault.webapp-inventory"][
        "validation_evidence"
    ]

    assert rows["compose.service.webapp"]["legacy_source"] == (
        "docker-compose.yml (service: webapp)"
    )
    assert rows["compose.service.webapp"]["category"] == "aces_sdl"
    assert "nodes.webapp" in rows["compose.service.webapp"]["aces_target"]
