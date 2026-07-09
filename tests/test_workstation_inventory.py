"""Checks for the SCN-010 workstation steady-state inventory bundle."""

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
WORKSTATION_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "workstation"
WORKSTATION_DOC_PATH = WORKSTATION_DIR / "README.md"
CAPTURE_SCRIPT_PATH = WORKSTATION_DIR / "capture-evidence.sh"
LEDGER_PATH = WORKSTATION_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = WORKSTATION_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:d5c817895ad61d42df871b71456d5209f08b9bc1bc62ddb1c14b4eb7685baf98"
IMAGE_DIGEST = f"aptl-workstation@{IMAGE_ID}"
BUILD_HISTORY_LAYER_COUNT = 41
SOURCE_INPUT_COUNT = 12
LOCAL_IDENTITY_USER_COUNT = 19
LOCAL_IDENTITY_GROUP_COUNT = 38
RUNTIME_PACKAGE_COUNT = 261
TRIVY_FINDING_COUNT = 42
FILESYSTEM_ENTRY_COUNT = 192
WORKSTATION_CONTENT_COUNT = 185
SERVICE_MANAGER_UNIT_COUNT = 73

REQUIRED_EVIDENCE_FILES = {
    "captured-at-utc.txt",
    "capture-limits.txt",
    "compose-service.workstation.json",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-internal.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.workstation-home.json",
    "docker-volume.workstation-logs.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-sensitive-paths.txt",
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
    "rpm-repositories.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json.gz",
    "syft-version.json",
    "systemd-units.txt",
    "trivy-sbom.cyclonedx.json.gz",
    "trivy-version.txt",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}

WORKSTATION_CLIENT_KEYS_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


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


def _systemd_unit_file_names() -> set[str]:
    text = (EVIDENCE_DIR / "systemd-units.txt").read_text(encoding="utf-8")
    unit_file_text, _status_text = text.split("\n--service-status--\n", maxsplit=1)
    names = set()
    for line in unit_file_text.splitlines():
        if not line or line.startswith("UNIT FILE") or line.endswith("unit files listed."):
            continue
        parts = line.split()
        if parts and "." in parts[0]:
            names.add(parts[0])
    return names


def test_workstation_inventory_note_declares_scope_and_evidence():
    text = WORKSTATION_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #334",
        "aptl-workstation",
        "custom-build",
        "already-running local lab",
        "not as clean-lab rebuild proof",
        "Rocky Linux 9.8",
        "CAP_SYS_ADMIN",
        "seccomp:unconfined",
        "73 systemd service-manager unit records",
        "Brad-Edwards/aces#418 is merged and consumed",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "syft:location:*",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Workstation inventory note missing scope markers: {missing}"


def test_workstation_capture_script_pins_reproducible_toolchain_and_secret_capture():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "filesystem-sensitive-paths.txt",
        "evidence-sha256sums.txt",
        "syft:location:",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert os.name != "posix" or (CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111)


def test_workstation_mapping_ledger_validates_without_gap_triage():
    result = validate_mapping_ledger(WORKSTATION_DIR)
    assert result.ok, result.errors
    assert result.fact_count == 19
    assert result.encoded_count == 19
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["workstation.runtime.service-manager-state"] == "encoded"
    service_manager_fact = next(
        fact
        for fact in ledger["facts"]
        if fact["id"] == "workstation.runtime.service-manager-state"
    )
    assert "nodes.techvault.workstation.runtime.service_manager_units" in service_manager_fact[
        "aces"
    ]["fields"]


def test_workstation_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(WORKSTATION_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_workstation_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_workstation_evidence_sha256_manifest_matches_files():
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


def test_workstation_mapping_ledger_references_every_evidence_file():
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


def test_workstation_evidence_commits_scenario_secret_material():
    container = _json_file("docker-inspect.container.json")[0]
    history = (EVIDENCE_DIR / "docker-history.image.txt").read_text(encoding="utf-8")
    sensitive_paths = (EVIDENCE_DIR / "filesystem-sensitive-paths.txt").read_text(encoding="utf-8")
    filesystem_checksums = (EVIDENCE_DIR / "filesystem-checksums.txt").read_text(encoding="utf-8")

    # SandboxKey is a per-recreate Docker netns path; the CTF flags are
    # regenerated per container start. Assert shape, not the volatile value.
    # See techvault-inventory-volatility.md.
    assert re.match(
        r"^/var/run/docker/netns/[0-9a-f]+$",
        container["NetworkSettings"]["SandboxKey"],
    )
    assert 'echo "dev-user:Summer2024" | chpasswd' in history
    assert re.search(r"APTL\{user_workstation_[0-9a-f]{32}\}", sensitive_paths)
    assert re.search(r"APTL\{root_workstation_[0-9a-f]{32}\}", sensitive_paths)
    assert "techvault_db_pass" in sensitive_paths
    assert "techvault-jwt-weak" in sensitive_paths
    assert "tvault-api-key-2024-admin" in sensitive_paths
    assert "AKIAIOSFODNN7EXAMPLE" in sensitive_paths
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in sensitive_paths
    # SEC #417: the target /keys holds only public key material.
    assert "--path:/keys/aptl_lab_key.pub--" in sensitive_paths
    assert "--path:/keys/kali_pivot_key.pub--" in sensitive_paths
    assert "--path:/keys/aptl_lab_key--" not in sensitive_paths
    assert "--path:/keys/authorized_keys--" not in sensitive_paths
    assert "--path:/home/dev-user/.ssh/id_rsa--" in sensitive_paths
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in sensitive_paths
    assert "--path:/var/ossec/etc/client.keys--" in sensitive_paths
    assert f"{WORKSTATION_CLIENT_KEYS_DIGEST}  /var/ossec/etc/client.keys" in filesystem_checksums
    assert "<REDACTED" not in sensitive_paths
    assert "<REDACTED" not in history


def test_workstation_container_runtime_state_and_identity():
    container = _json_file("docker-inspect.container.json")[0]
    assert container["Name"] == "/aptl-workstation"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "ws01.techvault.local"
    assert container["Config"]["Entrypoint"] == ["/usr/local/bin/entrypoint.sh"]
    assert container["Config"]["Cmd"] == ["/usr/sbin/init"]
    assert container["HostConfig"]["Memory"] == 268435456
    assert container["HostConfig"]["MemorySwap"] == 536870912
    assert container["HostConfig"]["CapAdd"] == [
        "CAP_SYS_ADMIN",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
    ]
    assert container["HostConfig"]["SecurityOpt"] == ["seccomp:unconfined"]
    assert container["HostConfig"]["CgroupnsMode"] == "host"
    assert "aptl_workstation_logs:/var/log:rw" in container["HostConfig"]["Binds"]
    assert container["NetworkSettings"]["Networks"]["aptl_aptl-internal"][
        "IPAddress"
    ] == "172.20.2.40"


def test_workstation_image_identity_and_source_package_are_recorded():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["/usr/local/bin/entrypoint.sh"]
    assert image["Config"]["Cmd"] == ["/usr/sbin/init"]
    assert "22/tcp" in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 30

    source_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(
        encoding="utf-8"
    )
    for source_path in (
        "containers/workstation/Dockerfile",
        "containers/workstation/setup-workstation.sh",
        "containers/workstation/lab-install.service",
        "containers/base/scripts/entrypoint-base.sh",
        "keys/aptl_lab_key.pub",
        "config/lab-ssh/kali_pivot_key.pub",
    ):
        assert source_path in source_checksums


def test_workstation_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        'PRETTY_NAME="Rocky Linux 9.8 (Blue Onyx)"',
        "uid=0(root)",
        "/usr/sbin/init",
        "/usr/lib/systemd/systemd-journald",
        "sshd: /usr/sbin/sshd -D",
        "0.0.0.0:22",
        "[::]:22",
        "/etc/sudoers.d/dev-user",
        "dev-user ALL=(ALL) NOPASSWD:ALL",
        "labadmin ALL=(ALL) NOPASSWD:ALL",
        "lab-install.service",
        "rsyslog.service",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_workstation_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"].lower(): item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"].lower() for item in vulnerabilities)

    # counts.json must stay internally consistent with the vuln list, but the
    # totals are per-Trivy-DB (refreshed externally, ~daily), so assert
    # structure, not the volatile totals. See techvault-inventory-volatility.md.
    assert counts == dict(computed)
    assert counts
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)


def test_workstation_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert syft_version["application"] == "syft"
    syft_location_properties = [
        prop
        for component in syft_sbom["components"]
        for prop in component.get("properties", [])
        if prop["name"].startswith("syft:location:")
    ]
    assert syft_location_properties == []


def test_workstation_osquery_evidence_records_requested_tables_and_limits():
    expected_tables = {
        "apt_sources",
        "docker_containers",
        "docker_images",
        "installed_applications",
        "listening_ports",
        "processes",
        "programs",
    }
    table_files = {
        path.name.removeprefix("osquery-").removesuffix(".json").replace("-", "_")
        for path in EVIDENCE_DIR.glob("osquery-*.json")
    }
    assert expected_tables <= table_files

    processes = _json_file("osquery-processes.json")
    process_names = {row["name"] for row in processes["rows"]}
    assert processes["status"] == "captured"
    assert {"systemd", "systemd-journal", "sshd"} <= process_names

    listening_ports = _json_file("osquery-listening-ports.json")
    assert listening_ports["status"] == "captured"
    assert any(row["port"] == "22" for row in listening_ports["rows"])

    docker_containers = _json_file("osquery-docker-containers.json")
    assert docker_containers["status"] == "captured"
    assert docker_containers["rows"][0]["name"] == "/aptl-workstation"

    docker_images = _json_file("osquery-docker-images.json")
    assert docker_images["status"] == "captured"
    assert any("aptl-workstation:latest" in row["tags"] for row in docker_images["rows"])

    assert _json_file("osquery-apt-sources.json")["status"] == "not_applicable"
    for name in ("installed-applications", "programs"):
        payload = _json_file(f"osquery-{name}.json")
        assert payload["status"] == "unavailable"
        assert payload["rows"] == []


def test_techvault_sdl_encodes_workstation_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    workstation = data["nodes"]["workstation"]
    runtime = workstation["runtime"]
    build = workstation["source"]["build"]

    assert workstation["source"]["name"] == "aptl-workstation"
    assert workstation["source"]["version"] == IMAGE_DIGEST
    assert build["base_image"] == "rockylinux:9"
    assert build["dockerfile_path"] == "containers/workstation/Dockerfile"
    assert len(build["instructions"]) == 40
    assert len(build["layers"]) == BUILD_HISTORY_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert len(build["copied_sources"]) == 9
    assert build["config"]["entrypoint"] == ["/usr/local/bin/entrypoint.sh"]
    assert build["config"]["command"] == ["/usr/sbin/init"]
    assert build["attestation"]["status"] == "absent"
    assert {
        "port": 22,
        "protocol": "tcp",
        "name": "ssh",
    } == {
        key: value
        for key, value in workstation["services"][0].items()
        if key != "description"
    }
    assert set(workstation["vulnerabilities"]) == {
        "workstation-bash-history-credential-disclosure",
        "workstation-pgpass-credential-disclosure",
        "workstation-hardcoded-app-secrets",
        "workstation-passwordless-private-key",
        "workstation-nopasswd-sudo",
    }

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert len(mounts) == 31
    # SEC #417: /keys is bound as two read-only public-key file mounts.
    assert mounts["/keys/aptl_lab_key.pub"]["source_kind"] == "bind"
    assert mounts["/keys/aptl_lab_key.pub"]["read_only"] is True
    assert mounts["/keys/kali_pivot_key.pub"]["read_only"] is True
    assert mounts["/var/log"]["source"] == "aptl_workstation_logs"
    assert mounts["/home"]["source_kind"] == "volume"
    assert mounts["/sys/fs/cgroup"]["source_kind"] == "bind"

    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert Counter(item["severity"] for item in runtime["package_vulnerabilities"]) == {
        "critical": 2,
        "high": 22,
        "medium": 17,
        "low": 1,
    }
    assert len(runtime["service_manager_units"]) == SERVICE_MANAGER_UNIT_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["local_identity"]["sudo_rules"]) == 2
    assert len([name for name in data["content"] if name.startswith("workstation-")]) == (
        WORKSTATION_CONTENT_COUNT
    )
    assert len([name for name in data["accounts"] if name.startswith("workstation-local-")]) == (
        LOCAL_IDENTITY_USER_COUNT
    )


def test_workstation_service_manager_units_match_systemd_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    units = {
        unit["unit_id"]: unit
        for unit in data["nodes"]["workstation"]["runtime"]["service_manager_units"]
    }
    assert len(units) == SERVICE_MANAGER_UNIT_COUNT
    assert {unit["unit_name"] for unit in units.values()} == _systemd_unit_file_names()

    lab_install = units["lab-install"]
    assert lab_install["unit_name"] == "lab-install.service"
    assert lab_install["load_state"] == "loaded"
    assert lab_install["active_state"] == "failed"
    assert lab_install["sub_state"] == "failed"
    assert lab_install["enabled_state"] == "enabled"
    assert lab_install["result"] == "exit_code"
    assert lab_install["exit_code"] == 1
    assert lab_install["unit_file_path"] == "/etc/systemd/system/lab-install.service"
    assert lab_install["exec_start"]["command"] == "/opt/purple-team/scripts/install-all.sh"

    rsyslog = units["rsyslog"]
    assert rsyslog["active_state"] == "failed"
    assert rsyslog["result"] == "exit_code"
    assert rsyslog["exit_code"] == 226
    assert rsyslog["status_text"] == "226/NAMESPACE"

    sshd = units["sshd"]
    assert sshd["active_state"] == "active"
    assert sshd["sub_state"] == "running"
    assert sshd["main_pid"] == 55
    assert sshd["service"] == "ssh"
    assert sshd["exec_start"]["command"] == "/usr/sbin/sshd"

    assert units["systemd-journald"]["active_state"] == "active"
    assert units["systemd-tmpfiles-clean"]["status_text"] == "243/CREDENTIALS"
    assert units["systemd-tmpfiles-setup"]["status_text"] == "243/CREDENTIALS"
    assert units["systemd-user-sessions"]["sub_state"] == "exited"
    assert units["wazuh-agent"]["active_state"] == "inactive"
    assert units["falco-modern-bpf"]["enabled_state"] == "disabled"
    assert units["arp-ethers"]["active_state"] == "unknown"


def test_workstation_filesystem_checksum_paths_are_encoded_as_content():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content_paths = {
        item["path"] for item in data["content"].values() if item["type"] == "file"
    }
    checksum_paths = {
        line.split("  ", maxsplit=1)[1]
        for line in (EVIDENCE_DIR / "filesystem-checksums.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    }
    assert checksum_paths <= content_paths


def test_workstation_filesystem_tree_is_encoded_as_runtime_inventory():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    filesystem = {
        entry["path"]: entry
        for entry in data["nodes"]["workstation"]["runtime"]["filesystem_inventory"]
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
        sdl_digest = filesystem[path]["content_digest"]
        # Runtime-written files (logs, flags, ssh keys, ossec.conf, client.keys)
        # churn every container run, so their SDL digest is intentionally left
        # unpinned (empty). Skip those; deterministic files stay pinned.
        # See techvault-inventory-volatility.md.
        if not sdl_digest:
            continue
        assert filesystem[path]["digest_algorithm"] == "sha256"
        assert sdl_digest == expected_digest


def test_workstation_passwd_users_are_encoded_as_accounts():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    account_usernames = {
        account["username"]
        for name, account in data["accounts"].items()
        if name.startswith("workstation-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames <= account_usernames


def test_workstation_runtime_local_identity_matches_passwd_and_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    local_identity = data["nodes"]["workstation"]["runtime"]["local_identity"]
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

    sudo_rules = {
        rule["principal"]: rule for rule in local_identity["sudo_rules"]
    }
    assert set(sudo_rules) == {"dev-user", "labadmin"}
    assert all(rule["nopasswd"] is True for rule in sudo_rules.values())


def test_workstation_runtime_network_matches_docker_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    network = data["nodes"]["workstation"]["runtime"]["network"]
    container = _json_file("docker-inspect.container.json")[0]
    observed = container["NetworkSettings"]["Networks"]["aptl_aptl-internal"]
    docker_network = _json_file("docker-network.aptl-internal.json")[0]

    assert network["hostname"] == container["Config"]["Hostname"]
    assert network["domainname"] == container["Config"]["Domainname"]
    endpoints = {endpoint["network"]: endpoint for endpoint in network["endpoints"]}
    endpoint = endpoints["internal-net"]
    # network_id, endpoint_id, mac_address, and the container-short-id entry in
    # dns_names are per-recreate volatile and left unpinned in the SDL. Assert
    # the evidence is internally consistent. See techvault-inventory-volatility.md.
    assert observed["NetworkID"] == docker_network["Id"]
    assert endpoint["ip_address"] == observed["IPAddress"] == "172.20.2.40"
    assert endpoint["ip_prefix_length"] == observed["IPPrefixLen"]
    assert endpoint["aliases"] == observed["Aliases"]
    assert endpoint["gateway"] == docker_network["IPAM"]["Config"][0]["Gateway"]
    assert network["published_ports"] == []


def test_techvault_sdl_parses_and_compiles_with_workstation_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.techvault.workstation"].spec["node"]
    runtime = node["runtime"]

    assert len(runtime["mounts"]) == 31
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["processes"]) == 3
    assert "process" not in runtime, (
        "ACES PR #458 removed runtime.process; PID 1 systemd-init identity is "
        "carried as processes[0]."
    )
    assert runtime["processes"][0]["name"] == "systemd-init"
    assert runtime["processes"][0]["pid"] == 1
    assert runtime["processes"][0]["command"] == ["/usr/sbin/init"]
    assert len(runtime["environment"]) == 6
    assert len(runtime["ssh_servers"]) == 1
    assert runtime["ssh_servers"][0]["ssh_server_id"] == "workstation-sshd", (
        "ACES PR #458 renamed server_id -> ssh_server_id on the typed "
        "runtime.ssh_servers family under the <noun>_id primary-id convention."
    )
    assert len(runtime["service_manager_units"]) == SERVICE_MANAGER_UNIT_COUNT
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    units = {unit["unit_id"]: unit for unit in runtime["service_manager_units"]}
    assert units["lab-install"]["result"] == "exit_code"
    assert units["sshd"]["service"] == "ssh"


def test_parity_inventory_cites_workstation_inventory_and_consumed_aces_gap():
    inventory = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in inventory["rows"]}

    row = rows["scen.techvault.workstation-inventory"]
    assert row["legacy_source"] == "scenarios/techvault.sdl.yaml"
    assert row["category"] == "aces_sdl"
    assert row["blocking_followup"] == "n/a"
    assert "docs/aces/inventory/workstation/" in row["validation_evidence"]
    assert "tests/test_workstation_inventory.py" in row["validation_evidence"]
    assert "Brad-Edwards/aces#418 consumed" in row["validation_evidence"]
    assert "runtime / content / accounts / relationships" in row["aces_target"]
