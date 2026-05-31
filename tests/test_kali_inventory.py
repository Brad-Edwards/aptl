"""Checks for the SCN-010 kali container steady-state inventory bundle."""

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
KALI_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "kali"
KALI_DOC_PATH = KALI_DIR / "README.md"
LEDGER_PATH = KALI_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = KALI_DIR / "evidence"
PREFLIGHT_PATH = PROJECT_ROOT / "docs" / "aces" / "inventory" / "kali-preflight.md"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:f524320106669c6885679587510652c8a78ca1961b7545692f0fa8f4695974b9"
IMAGE_DIGEST = f"aptl-kali@{IMAGE_ID}"

LEDGER_FACT_COUNT = 25
LEDGER_ENCODED_COUNT = 25
LEDGER_BLOCKED_COUNT = 0
CONSUMED_ACES_GAP_FACT_IDS = {
    "kali.runtime.init-process",
    "kali.runtime.seccomp",
    "kali.runtime.capsh-subtree-drop",
    "kali.runtime.ssh-server-config",
}

PACKAGE_COUNT = 947
GRYPE_FINDING_COUNT = 58
FILESYSTEM_ENTRY_COUNT = 20
MOUNT_COUNT = 29
LOCAL_IDENTITY_USER_COUNT = 27
LOCAL_IDENTITY_GROUP_COUNT = 48
NETWORK_ENDPOINT_COUNT = 3
EXTRA_HOSTS_COUNT = 9
BUILD_INSTRUCTION_COUNT = 24
BUILD_LAYER_COUNT = 33

REQUIRED_EVIDENCE_FILES = {
    "captured-at-utc.txt",
    "capture-limits.txt",
    "compose-service.kali.json",
    "docker-compose-version.json",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-dmz.json",
    "docker-network.aptl-internal.json",
    "docker-network.aptl-redteam.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.kali-captures.json",
    "docker-volume.kali-operations.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "grype-version.txt",
    "grype-vulnerability-counts.json",
    "grype-vulnerability-list.json",
    "language-manifests.txt",
    "os-packages.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "trivy-os-packages.json",
    "trivy-version.txt",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}


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


def test_kali_inventory_note_declares_scope_and_evidence():
    text = KALI_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #339",
        "aptl-kali",
        "custom-build",
        "rebuilt from current `containers/kali/` source",
        "not run `aptl lab stop -v &&",
        "Docker Compose service",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "docker-init",
        "auditd is installed",
        "auditd=degraded",
        "Grype",
        "kali-rolling",
        "ACES #384",
        "ACES #385",
        "ACES #386",
        "ACES #387",
        "ADR-027",
        "ADR-028",
        "ADR-030",
        "ADR-031",
        "No known ACES expressivity",
        "byte-identical rebuildability",
        "full Kali tool root filesystem",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Kali inventory note missing scope markers: {missing}"


def test_kali_preflight_artifact_is_present():
    text = PREFLIGHT_PATH.read_text(encoding="utf-8")
    for needle in ("SCN-010 / issue #339", "docs/aces/inventory/kali/"):
        assert needle in text, f"kali preflight missing {needle!r}"


def test_kali_mapping_ledger_validates_with_all_facts_encoded():
    result = validate_mapping_ledger(KALI_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_ENCODED_COUNT
    assert result.blocked_count == LEDGER_BLOCKED_COUNT
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["id"] == "kali"
    assert ledger["asset"]["aptl_issue"] == 339
    assert ledger["asset"]["source_class"] == "custom-build"
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    for fact_id in CONSUMED_ACES_GAP_FACT_IDS:
        assert dispositions[fact_id] == "encoded"
    assert dispositions["kali.runtime.vulnerability-scan"] == "encoded_with_caveat"
    assert dispositions["kali.runtime.capability-policy"] == "encoded"
    assert dispositions["kali.runtime.container-host-config"] == "encoded"


def test_kali_gap_report_surfaces_no_remaining_aces_gaps():
    report = gap_report(KALI_DIR)
    assert report["gaps"] == []
    assert not report["triage_needed"]


def test_kali_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_kali_evidence_sha256_manifest_matches_files():
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


def test_kali_evidence_carries_no_private_key_material():
    """ADR-029: the generated SSH private key is catalogued by checksum only."""
    key_marker = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file() and key_marker.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert not offenders, f"Private key material leaked into evidence: {offenders}"


def test_kali_container_runtime_state_and_security_surface():
    container = _json_file("docker-inspect.container.json")[0]
    host = container["HostConfig"]

    assert container["Name"] == "/aptl-kali"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Config"]["Hostname"] == "kali-redteam"
    assert host["Init"] is True
    assert host["SecurityOpt"] == ["seccomp:unconfined"]
    assert set(host["CapAdd"]) == {
        "CAP_AUDIT_CONTROL",
        "CAP_AUDIT_WRITE",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_SYS_PACCT",
    }
    assert host["RestartPolicy"]["Name"] == "unless-stopped"
    assert host["Memory"] == 1073741824
    assert host["PortBindings"] in ({}, None)
    assert len(host["ExtraHosts"]) == EXTRA_HOSTS_COUNT
    networks = container["NetworkSettings"]["Networks"]
    assert networks["aptl_aptl-redteam"]["IPAddress"] == "172.20.4.30"
    assert networks["aptl_aptl-dmz"]["IPAddress"] == "172.20.1.30"
    assert networks["aptl_aptl-internal"]["IPAddress"] == "172.20.2.35"


def test_kali_image_identity_and_source_package_are_recorded():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["/entrypoint.sh"]
    assert "22/tcp" in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 18

    source_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(
        encoding="utf-8"
    )
    for source_path in (
        "containers/kali/Dockerfile",
        "containers/kali/entrypoint.sh",
        "containers/kali/healthcheck.sh",
        "containers/kali/audit/aptl.rules",
        "containers/kali/scripts/aptl-wrap-shell.sh",
    ):
        assert source_path in source_checksums


def test_kali_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        "VERSION_CODENAME=kali-rolling",
        "/sbin/docker-init -- /entrypoint.sh",
        "sleep infinity",
        "sshd: /usr/sbin/sshd",
        "0.0.0.0:22",
        "forcecommand /usr/local/bin/aptl-wrap-shell.sh",
        "acceptenv APTL_SESSION_ID",
        "auditd=degraded",
        "procacct=ok",
        "kali ALL=(ALL) NOPASSWD:ALL",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_kali_grype_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("grype-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("grype-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)

    assert counts == dict(computed)
    assert sum(counts.values()) == len(vulnerabilities) == GRYPE_FINDING_COUNT
    assert counts == {"critical": 1, "high": 12, "medium": 26, "low": 19}
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)


def test_kali_trivy_zero_findings_is_recorded_as_a_scanner_limit():
    """Trivy 0.70.0 has no advisory DB for kali-rolling; the 0 result is kept."""
    assert _json_file("trivy-vulnerability-list.json") == []
    assert _json_file("trivy-vulnerability-counts.json") == []
    assert len(_json_file("trivy-os-packages.json")) == PACKAGE_COUNT
    limits = (EVIDENCE_DIR / "capture-limits.txt").read_text(encoding="utf-8")
    assert "for the rolling `kali-rolling` release" in limits
    assert "Grype 0.112.0 as the primary scanner" in limits


def test_techvault_sdl_encodes_kali_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    assert data["name"] == "techvault"

    kali = data["nodes"]["kali"]
    assert kali["type"] == "VM"
    assert kali["os"] == "linux"
    assert kali["source"]["name"] == "aptl-kali"
    assert kali["source"]["version"] == IMAGE_DIGEST
    assert {"port": 22, "protocol": "tcp", "name": "ssh"} in kali["services"]
    assert "vulnerabilities" not in kali, "kali is the attacker node, not a target"

    build = kali["source"]["build"]
    assert build["base_image"] == "kalilinux/kali-last-release:latest"
    assert build["dockerfile_path"] == "containers/kali/Dockerfile"
    assert len(build["instructions"]) == BUILD_INSTRUCTION_COUNT
    assert len(build["layers"]) == BUILD_LAYER_COUNT
    assert build["config"]["working_directory"] == "/home/kali"
    assert "22/tcp" in build["config"]["exposed_ports"]
    assert build["attestation"]["status"] == "absent"

    runtime = kali["runtime"]
    assert len(runtime["mounts"]) == MOUNT_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["packages"]) == PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == GRYPE_FINDING_COUNT
    assert {item["severity"] for item in runtime["package_vulnerabilities"]} <= {
        "critical",
        "high",
        "medium",
        "low",
    }
    assert all(
        finding["scanner"] == "grype" for finding in runtime["package_vulnerabilities"]
    )

    container = runtime["container"]
    assert container["runtime_name"] == "runc"
    assert container["privileged"] is False
    assert len(container["extra_hosts"]) == EXTRA_HOSTS_COUNT
    extra_hosts = {host["hostname"]: host["address"] for host in container["extra_hosts"]}
    assert extra_hosts["techvault.local"] == "172.20.2.10"
    assert extra_hosts["db.techvault.local"] == "172.20.2.11"

    # ACES #384 / ADR-027 — Docker init / PID-1 reaper.
    init_process = container["init_process"]
    assert init_process["enabled"] is True
    assert init_process["implementation"] == "docker-init"
    assert init_process["executable_path"] == "/sbin/docker-init"
    assert init_process["reaps_children"] is True
    assert init_process["argv"] == ["/sbin/docker-init", "--", "/entrypoint.sh"]

    # ACES #385 / ADR-028 — seccomp + security_opt posture.
    assert container["seccomp_profile"] == "unconfined"
    assert container["security_opt"] == ["seccomp:unconfined"]

    assert "process" not in runtime, (
        "ACES PR #458 removed runtime.process; PID 1 docker-init identity is "
        "carried as processes[0]."
    )
    assert runtime["processes"][0]["name"] == "docker-init"
    assert runtime["processes"][0]["pid"] == 1
    assert runtime["processes"][0]["command"] == ["/sbin/docker-init", "--", "/entrypoint.sh"]
    process_names = {process["name"] for process in runtime["processes"]}
    assert {"docker-init", "sshd"} <= process_names

    caps = runtime["linux_capabilities"]
    assert set(caps["add"]) == {
        "CAP_AUDIT_CONTROL",
        "CAP_AUDIT_WRITE",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_SYS_PACCT",
    }
    # ACES #386 / ADR-030 — capsh per-subtree capability drop.
    overrides = caps["process_overrides"]
    assert len(overrides) == 1
    sshd_override = overrides[0]
    assert sshd_override["subject"]["name"] == "sshd"
    assert sshd_override["scope"] == "subtree"
    assert sshd_override["drop"] == ["CAP_AUDIT_CONTROL"]

    # ACES #387 / ADR-031 — sshd policy surface.
    ssh_servers = runtime["ssh_servers"]
    assert len(ssh_servers) == 1
    sshd = ssh_servers[0]
    assert sshd["ssh_server_id"] == "kali-sshd", (
        "ACES PR #458 renamed server_id -> ssh_server_id under the <noun>_id "
        "primary-id convention."
    )
    assert sshd["service"] == "ssh"
    assert "APTL_SESSION_ID" in sshd["accept_env"]
    assert "APTL_RUN_ID" in sshd["accept_env"]
    assert "APTL_TRACE_ID" in sshd["accept_env"]
    assert sshd["allow_users"] == ["kali"]
    assert sshd["password_authentication"] is False
    assert sshd["pubkey_authentication"] is True
    assert len(sshd["match_rules"]) == 1
    match = sshd["match_rules"][0]
    assert match["match_id"] == "kali-user-forcecommand"
    assert match["criteria"][0]["kind"] == "user"
    assert match["criteria"][0]["pattern"] == "kali"
    assert match["forced_command"]["command_kind"] == "absolute_path"
    assert match["forced_command"]["command"] == "/usr/local/bin/aptl-wrap-shell.sh"

    assert runtime["operational_policy"]["restart"] == "unless_stopped"
    assert runtime["operational_policy"]["resource_limits"]["memory"] == 1073741824
    assert runtime["health"]["status"] == "healthy"

    network = runtime["network"]
    assert network["hostname"] == "kali-redteam"
    assert len(network["endpoints"]) == NETWORK_ENDPOINT_COUNT
    assert network["published_ports"] == []
    endpoints = {endpoint["network"]: endpoint for endpoint in network["endpoints"]}
    assert endpoints["redteam-net"]["ip_address"] == "172.20.4.30"
    assert endpoints["dmz-net"]["ip_address"] == "172.20.1.30"
    assert endpoints["internal-net"]["ip_address"] == "172.20.2.35"

    local_identity = runtime["local_identity"]
    assert len(local_identity["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(local_identity["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    users = {user["username"]: user for user in local_identity["users"]}
    assert users["kali"]["uid"] == 1000
    assert users["root"]["uid"] == 0

    infrastructure = data["infrastructure"]
    assert infrastructure["kali"]["links"] == ["redteam-net", "dmz-net", "internal-net"]
    assert "redteam-net" in data["nodes"]
    assert data["nodes"]["redteam-net"]["type"] == "Switch"
    assert "kali-healthcheck" in data["conditions"]

    accounts = data["accounts"]
    kali_accounts = {
        name: account
        for name, account in accounts.items()
        if account.get("node") == "kali"
    }
    assert len(kali_accounts) == LOCAL_IDENTITY_USER_COUNT
    assert any(account["username"] == "kali" for account in kali_accounts.values())


def test_techvault_sdl_filesystem_inventory_matches_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    filesystem = {
        entry["path"]: entry
        for entry in data["nodes"]["kali"]["runtime"]["filesystem_inventory"]
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
        assert filesystem[path]["content_digest"] == expected_digest
    assert filesystem["/home/kali/.ssh/id_rsa"]["sensitivity"] == "secret_fixture"


def test_kali_passwd_users_are_encoded_as_accounts():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    account_usernames = {
        account["username"]
        for account in data["accounts"].values()
        if account.get("node") == "kali"
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0] for line in _runtime_baseline_section("users")
    }
    assert passwd_usernames == account_usernames


def test_techvault_sdl_parses_and_compiles_with_kali_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.kali"].spec["node"]
    runtime = node["runtime"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(runtime["packages"]) == PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == GRYPE_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["mounts"]) == MOUNT_COUNT
    assert len(runtime["network"]["endpoints"]) == NETWORK_ENDPOINT_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["container"]["extra_hosts"]) == EXTRA_HOSTS_COUNT
    assert runtime["container"]["init_process"]["enabled"] is True
    assert runtime["container"]["seccomp_profile"] == "unconfined"
    assert len(runtime["linux_capabilities"]["process_overrides"]) == 1
    assert len(runtime["ssh_servers"]) == 1


def test_parity_inventory_cites_kali_inventory_and_aces_sdl():
    inventory = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in inventory["rows"]}

    kali_row = rows["scen.techvault.kali-inventory"]
    assert kali_row["legacy_source"] == "scenarios/techvault.sdl.yaml"
    assert kali_row["category"] == "aces_sdl"
    assert "docs/aces/inventory/kali/" in kali_row["validation_evidence"]
    assert kali_row["blocking_followup"] == "n/a"
    for issue in ("#384", "#385", "#386", "#387"):
        assert issue in kali_row["validation_evidence"]

    assert rows["compose.profile.kali"]["category"] == "aces_sdl"
    assert "nodes.kali" in rows["compose.profile.kali"]["aces_target"]
    assert rows["compose.profile.kali"]["blocking_followup"] == "n/a"
