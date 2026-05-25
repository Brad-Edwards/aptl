"""Checks for the SCN-010 AD steady-state inventory bundle."""

from collections import Counter
from pathlib import Path
import gzip
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
PREFLIGHT_PATH = PROJECT_ROOT / "docs" / "aces" / "inventory" / "ad-preflight.md"
AD_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "ad"
AD_DOC_PATH = AD_DIR / "README.md"
LEDGER_PATH = AD_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = AD_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:5806c59b401c045391be53c0d3e0c4feb6304030e716ff3b12b79415fbb1b052"
IMAGE_DIGEST = f"aptl-ad@{IMAGE_ID}"
FULL_TRIVY_FINDING_COUNT = 140
FULL_RUNTIME_PACKAGE_COUNT = 257
DOMAIN_USER_COUNT = 15
DOMAIN_GROUP_COUNT = 45
AD_BUILD_HISTORY_LAYER_COUNT = 23
AD_RUNTIME_MOUNT_COUNT = 27
AD_RUNTIME_FILESYSTEM_ENTRY_COUNT = 134
AD_LOCAL_IDENTITY_USER_COUNT = 22
AD_LOCAL_IDENTITY_GROUP_COUNT = 46
AD_IDENTITY_AUTHORITY_SERVICE_COUNT = 19
AD_IDENTITY_AUTHORITY_RELATIONSHIP_COUNT = 32

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.ad.json",
    "docker-compose-version.json",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-internal.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.ad-data.json",
    "docker-volume.ad-logs.json",
    "evidence-sha256sums.txt",
    "filesystem-checksums.txt",
    "filesystem-tree.txt",
    "language-manifests.txt",
    "os-packages.txt",
    "runtime-baseline.txt",
    "source-checksums.txt",
    "trivy-version.txt",
    "trivy-vulnerabilities.json.gz",
    "trivy-vulnerability-counts.json",
    "trivy-vulnerability-list.json",
}

SECRET_NEEDLES = (
    "Admin123!",
    "APTL{",
    "aptl:v1:ad",
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
)


def _json_file(name: str):
    with (EVIDENCE_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def _yaml_file(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def _runtime_baseline_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    _, rest = text.split(marker, maxsplit=1)
    next_marker = re.search(r"\n--[a-z-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def _samba_group_members() -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    current: str | None = None
    for line in _runtime_baseline_section("samba-group-members"):
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            groups[current] = []
        elif current:
            groups[current].append(line)
    return groups


def _samba_user_details() -> dict[str, dict[str, str | list[str]]]:
    details: dict[str, dict[str, str | list[str]]] = {}
    current: str | None = None
    for line in _runtime_baseline_section("samba-user-details"):
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            details[current] = {}
            continue
        if current is None or ": " not in line:
            continue
        key, value = line.split(": ", maxsplit=1)
        existing = details[current].get(key)
        if existing is None:
            details[current][key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            details[current][key] = [existing, value]
    return details


def test_ad_preflight_artifact_records_local_guardrails():
    text = PREFLIGHT_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010 / issue #332",
        "gc_codex_architecture_preflight",
        "docs/aces/inventory/ad/",
        "scenarios/techvault.sdl.yaml",
        "Do not create an APTL-local schema",
        "Redact AD administrator credentials",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"AD preflight missing guardrails: {missing}"


def test_ad_inventory_note_declares_scope_and_evidence():
    text = AD_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #332",
        "aptl-ad",
        "custom-build",
        "fresh local lab",
        "uv run aptl lab stop -v -y && uv run aptl lab start --skip-seed",
        "Samba Active Directory Domain Controller",
        "CAP_SYS_ADMIN",
        "CAP_NET_ADMIN",
        "mapping-ledger.yaml",
        "aptl aces-inventory validate",
        "runtime.identity_authorities",
        "Brad-Edwards/aces#401",
        "No known ACES expressivity gap remains",
        "full observed runtime mount table",
        "schema secret-safety boundary",
        "claim-bounded AD steady-state inventory facts",
        "Raw credential, key, and flag contents are intentionally absent",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"AD inventory note missing scope markers: {missing}"


def test_ad_mapping_ledger_validates_and_tracks_gap_handoff():
    result = validate_mapping_ledger(AD_DIR)
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
    assert dispositions["ad.runtime.domain-state"] == "encoded"
    assert dispositions["ad.runtime.local-identity"] == "encoded"
    assert dispositions["ad.runtime.package-inventory"] == "encoded_with_caveat"
    assert dispositions["ad.runtime.vulnerability-scan"] == "encoded_with_caveat"
    assert dispositions["ad.vulnerability.inventory"] == "encoded"
    domain_state = next(
        fact for fact in ledger["facts"] if fact["id"] == "ad.runtime.domain-state"
    )
    assert (
        "nodes.ad.runtime.identity_authorities.techvault-domain"
        in domain_state["aces"]["fields"]
    )


def test_ad_gap_report_surfaces_remaining_aces_gaps_only():
    report = gap_report(AD_DIR)
    assert report["gaps"] == []
    assert not report["triage_needed"]


def test_ad_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_ad_evidence_sha256_manifest_matches_files():
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


def test_ad_os_package_inventory_is_well_formed_and_encoded():
    package_path = EVIDENCE_DIR / "os-packages.txt"
    package_lines = package_path.read_text(encoding="utf-8").splitlines()
    parsed = [line.split("\t") for line in package_lines]

    assert len(package_lines) == FULL_RUNTIME_PACKAGE_COUNT
    assert all(len(row) == 3 and all(field for field in row) for row in parsed)
    package_names = {row[0] for row in parsed}
    assert {"dpkg", "samba", "winbind", "wazuh-agent"} <= package_names

    data = _yaml_file(TECHVAULT_SDL_PATH)
    runtime_packages = data["nodes"]["ad"]["runtime"]["packages"]
    assert len(runtime_packages) == FULL_RUNTIME_PACKAGE_COUNT
    assert {package["name"] for package in runtime_packages} == package_names


def test_ad_evidence_does_not_contain_raw_secret_material():
    offenders = {}
    raw_assignment = re.compile(
        r"^(SAMBA_ADMIN_PASSWORD|APTL_FLAG_KEY)=(?!<REDACTED).+",
        re.MULTILINE,
    )
    for path in EVIDENCE_DIR.iterdir():
        if not path.is_file():
            continue
        text = _evidence_text(path)
        leaked = [needle for needle in SECRET_NEEDLES if needle in text]
        leaked.extend(match.group(1) for match in raw_assignment.finditer(text))
        if leaked:
            offenders[path.name] = sorted(set(leaked))
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_ad_container_runtime_state_and_redaction_boundary():
    container = _json_file("docker-inspect.container.json")[0]
    env = "\n".join(container["Config"]["Env"])

    assert container["Name"] == "/aptl-ad"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "dc.techvault.local"
    assert container["HostConfig"]["Memory"] == 536870912
    assert set(container["HostConfig"]["CapAdd"]) == {"CAP_NET_ADMIN", "CAP_SYS_ADMIN"}
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert "aptl_ad_data:/var/lib/samba:rw" in container["HostConfig"]["Binds"]
    assert "aptl_ad_logs:/var/log/samba:rw" in container["HostConfig"]["Binds"]
    assert container["HostConfig"]["PortBindings"] == {}
    assert re.search(
        r"^SAMBA_ADMIN_PASSWORD=<REDACTED-SCENARIO-FIXTURE>$",
        env,
        re.MULTILINE,
    )
    assert (
        container["NetworkSettings"]["Networks"]["aptl_aptl-internal"]["IPAddress"]
        == "172.20.2.10"
    )


def test_ad_image_identity_and_source_package_are_recorded():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["/opt/setup-ad.sh"]
    for port in ("53/tcp", "53/udp", "88/tcp", "389/tcp", "445/tcp"):
        assert port in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 13

    source_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(
        encoding="utf-8"
    )
    assert "containers/ad/Dockerfile" in source_checksums
    assert "containers/ad/setup-ad.sh" in source_checksums
    assert "containers/ad/provision-users.sh" in source_checksums
    assert "containers/_wazuh-agent/wazuh-agent.sh" in source_checksums


def test_ad_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        "Ubuntu 22.04.5 LTS",
        "Version 4.15.13-Ubuntu",
        "Forest           : techvault.local",
        "Netbios domain   : TECHVAULT",
        "Account lockout threshold (attempts): 10",
        "OU=ServiceAccounts,OU=TechVault",
        "jessica.williams",
        "michael.thompson",
        "svc-backup",
        "MSSQLSvc/db.techvault.local:1433",
        "HTTP/webapp.techvault.local",
        "0.0.0.0:389",
        "0.0.0.0:445",
        "rsyslog                          RUNNING",
        "samba                            RUNNING",
        "wazuh-agent                      RUNNING",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"

    assert len(_runtime_baseline_section("samba-users")) == DOMAIN_USER_COUNT
    assert len(_runtime_baseline_section("samba-groups")) == DOMAIN_GROUP_COUNT


def test_ad_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)
    with gzip.open(EVIDENCE_DIR / "trivy-vulnerabilities.json.gz", "rt") as fh:
        raw_report = json.load(fh)

    assert counts == dict(computed)
    assert len(vulnerabilities) == FULL_TRIVY_FINDING_COUNT
    assert counts == {"LOW": 75, "MEDIUM": 65}
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)
    assert raw_report["SchemaVersion"] == 2
    assert any(result.get("Vulnerabilities") for result in raw_report["Results"])


def test_techvault_sdl_encodes_ad_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    ad = data["nodes"]["ad"]
    runtime = ad["runtime"]
    accounts = data["accounts"]
    build = ad["source"]["build"]

    assert ad["source"]["version"] == IMAGE_DIGEST
    assert build["base_image"] == "ubuntu:22.04"
    assert build["dockerfile_path"] == "containers/ad/Dockerfile"
    assert len(build["layers"]) == AD_BUILD_HISTORY_LAYER_COUNT
    assert build["config"]["entrypoint"] == ["/opt/setup-ad.sh"]
    assert build["attestation"]["status"] == "absent"
    assert ad["os_version"] == "Ubuntu 22.04.5 LTS"
    assert set(ad["vulnerabilities"]) == {
        "ad-weak-password-jessica",
        "ad-seasonal-password-michael",
        "ad-contractor-overprivileged",
        "ad-former-employee-enabled",
        "ad-kerberoast-svc-sql",
        "ad-kerberoast-svc-web",
        "ad-domain-admin-svc-backup",
        "ad-domain-admin-devops",
    }
    service_ports = {(service["port"], service["protocol"]) for service in ad["services"]}
    assert (53, "tcp") in service_ports
    assert (88, "tcp") in service_ports
    assert (389, "tcp") in service_ports
    assert (445, "tcp") in service_ports

    assert len(runtime["packages"]) == FULL_RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == FULL_TRIVY_FINDING_COUNT
    severity_counts = Counter(
        finding["severity"] for finding in runtime["package_vulnerabilities"]
    )
    assert dict(severity_counts) == {
        "low": 75,
        "medium": 65,
    }
    assert set(runtime["linux_capabilities"]["add"]) == {
        "CAP_SYS_ADMIN",
        "CAP_NET_ADMIN",
    }
    assert len(runtime["mounts"]) == AD_RUNTIME_MOUNT_COUNT
    assert len(runtime["filesystem_inventory"]) == AD_RUNTIME_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == AD_LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == AD_LOCAL_IDENTITY_GROUP_COUNT
    assert runtime["local_identity"]["sudo_rules"] == []
    assert runtime["container"]["runtime_name"] == "runc"
    assert runtime["container"]["autoremove"] is False
    assert runtime["container"]["shm_size"] == 67108864
    assert runtime["health"]["status"] == "healthy"
    assert runtime["health"]["failing_streak"] == 0
    assert len(runtime["health"]["log"]) == 5
    assert runtime["operational_policy"]["resource_limits"] == {
        "memory": 536870912,
        "memory_swap": 1073741824,
    }
    assert runtime["network"]["endpoints"][0]["ip_address"] == "172.20.2.10"

    authority = runtime["identity_authorities"][0]
    assert authority["authority_id"] == "techvault-domain"
    assert authority["kind"] == "domain"
    assert authority["domain_name"] == "TECHVAULT"
    assert authority["realm"] == "TECHVAULT.LOCAL"
    assert authority["base_dn"] == "DC=techvault,DC=local"
    assert len(authority["services"]) == AD_IDENTITY_AUTHORITY_SERVICE_COUNT
    assert len(authority["relationships"]) == AD_IDENTITY_AUTHORITY_RELATIONSHIP_COUNT
    subjects = {subject["subject_id"]: subject for subject in authority["subjects"]}
    group_count = sum(
        1 for subject in subjects.values() if subject["kind"] == "group"
    )
    assert group_count == DOMAIN_GROUP_COUNT
    assert {"domain-admins", "domain-users", "it-admins", "vpn-users"} <= set(subjects)
    assert subjects["svc-sql"]["service_principal_names"] == [
        "MSSQLSvc/db.techvault.local:1433",
        "MSSQLSvc/db.techvault.local",
    ]
    assert subjects["svc-web"]["service_principal_names"] == [
        "HTTP/webapp.techvault.local",
    ]
    assert subjects["former-employee"]["enabled"] is True
    policy_settings = {
        setting["name"]: setting["values"]
        for policy in authority["policies"]
        for setting in policy["settings"]
    }
    assert policy_settings["threshold_attempts"] == ["10"]
    assert policy_settings["duration_minutes"] == ["30"]

    assert accounts["ad-domain-svc-sql"]["spn"] == "MSSQLSvc/db.techvault.local:1433"
    assert "MSSQLSvc/db.techvault.local" in accounts["ad-domain-svc-sql"]["description"]
    assert accounts["ad-domain-svc-web"]["spn"] == "HTTP/webapp.techvault.local"
    assert "ad-domain-admin-svc-backup" in accounts["ad-domain-svc-backup"][
        "description"
    ]
    assert accounts["ad-domain-jessica-williams"]["groups"] == []
    assert {
        "ad-domain-administrator",
        "ad-domain-emily-chen",
        "ad-domain-svc-backup",
    } <= {
        account_id
        for account_id, account in accounts.items()
        if "Domain Admins" in account.get("groups", [])
    }


def test_techvault_sdl_encodes_ad_content_accounts_and_relationships():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content = data["content"]
    accounts = data["accounts"]
    relationships = data["relationships"]
    authority = data["nodes"]["ad"]["runtime"]["identity_authorities"][0]
    authority_relationships = {
        (rel["source_ref"], rel["target_ref"]): rel["relationship_type"]
        for rel in authority["relationships"]
    }

    assert content["ad-file-opt-setup-ad-sh"]["source"]["version"].startswith("sha256:")
    assert content["ad-file-opt-flags-user-txt"]["sensitive"] is True
    assert accounts["ad-domain-jessica-williams"]["password_strength"] == "weak"
    assert accounts["ad-domain-jessica-williams"]["groups"] == []
    assert "ad-kerberoast-svc-sql" in accounts["ad-domain-svc-sql"]["description"]
    assert authority_relationships[("emily-chen", "domain-admins")] == "member_of"
    assert authority_relationships[("svc-backup", "domain-admins")] == "member_of"
    assert authority_relationships[("contractor-temp", "remote-desktop")] == "member_of"
    unsupported_jessica_memberships = {
        ("jessica-williams", "sales"),
        ("jessica-williams", "vpn-users"),
        ("jessica-williams", "domain-users"),
    }
    assert unsupported_jessica_memberships.isdisjoint(authority_relationships)
    assert relationships["ad-forwards-wazuh"]["target"] == "wazuh-manager"
    assert relationships["ad-provides-domain"]["type"] == "connects_to"
    assert relationships["ad-provides-domain"]["properties"]["realm"] == "TECHVAULT.LOCAL"


def test_ad_filesystem_checksum_paths_are_encoded_as_content():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content_paths = {
        item["path"]
        for item in data["content"].values()
        if item["type"] == "File" and item.get("target") == "ad"
    }
    checksum_paths = {
        line.split("  ", maxsplit=1)[1]
        for line in (EVIDENCE_DIR / "filesystem-checksums.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    }
    assert checksum_paths <= content_paths


def test_ad_filesystem_tree_is_encoded_as_runtime_inventory():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    filesystem = {
        entry["path"]: entry
        for entry in data["nodes"]["ad"]["runtime"]["filesystem_inventory"]
    }
    observed_paths = set()
    for line in (EVIDENCE_DIR / "filesystem-tree.txt").read_text(
        encoding="utf-8"
    ).splitlines():
        match = re.match(r"^\S+\s+\S+\s+\S+\s+\d+\s+\S+\s+(.+?)\s+->$", line)
        assert match, f"Unexpected filesystem tree row: {line}"
        observed_paths.add(match.group(1))

    assert len(filesystem) == AD_RUNTIME_FILESYSTEM_ENTRY_COUNT
    assert observed_paths <= filesystem.keys()
    for digest_line in (
        (EVIDENCE_DIR / "filesystem-checksums.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        expected_digest, path = digest_line.split("  ", maxsplit=1)
        assert filesystem[path]["digest_algorithm"] == "sha256"
        assert filesystem[path]["content_digest"] == expected_digest


def test_ad_runtime_mount_targets_are_encoded():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    mount_targets = {
        mount["target"] for mount in data["nodes"]["ad"]["runtime"]["mounts"]
    }
    observed_targets = set()
    for line in _runtime_baseline_section("mounts"):
        match = re.match(r".+? on (\S+) type \S+ \(", line)
        if match:
            observed_targets.add(match.group(1))

    assert len(mount_targets) == AD_RUNTIME_MOUNT_COUNT
    assert observed_targets <= mount_targets


def test_ad_runtime_local_identity_matches_passwd_and_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    local_identity = data["nodes"]["ad"]["runtime"]["local_identity"]
    encoded_users = {user["username"]: user for user in local_identity["users"]}
    encoded_groups = {group["name"]: group for group in local_identity["groups"]}

    group_rows = {}
    gid_names = {}
    for line in _runtime_baseline_section("local-group"):
        name, _password, gid, members = line.split(":")
        member_list = [member for member in members.split(",") if member]
        group_rows[name] = {"gid": int(gid), "members": member_list}
        gid_names[int(gid)] = name

    assert len(encoded_groups) == AD_LOCAL_IDENTITY_GROUP_COUNT
    assert set(encoded_groups) == set(group_rows)
    for name, expected in group_rows.items():
        assert encoded_groups[name]["gid"] == expected["gid"]
        assert encoded_groups[name]["members"] == expected["members"]

    passwd_rows = {}
    for line in _runtime_baseline_section("local-passwd"):
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

    assert len(encoded_users) == AD_LOCAL_IDENTITY_USER_COUNT
    assert set(encoded_users) == set(passwd_rows)
    for username, expected in passwd_rows.items():
        encoded = encoded_users[username]
        for field, value in expected.items():
            if field == "gecos" and not value:
                assert encoded.get(field, "") == ""
            else:
                assert encoded[field] == value

    assert local_identity["sudo_rules"] == []


def test_ad_passwd_users_are_encoded_as_accounts():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    account_usernames = {
        account["username"]
        for name, account in data["accounts"].items()
        if name.startswith("ad-local-")
    }
    passwd_usernames = {
        line.split(":", maxsplit=1)[0]
        for line in _runtime_baseline_section("local-passwd")
    }
    assert passwd_usernames <= account_usernames


def test_ad_runtime_network_matches_docker_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    network = data["nodes"]["ad"]["runtime"]["network"]
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
    assert endpoint["ip_address"] == observed["IPAddress"] == "172.20.2.10"
    assert endpoint["ip_prefix_length"] == observed["IPPrefixLen"]
    assert endpoint["mac_address"] == observed["MacAddress"]
    assert endpoint["aliases"] == observed["Aliases"]
    assert endpoint["dns_names"] == observed["DNSNames"]
    assert endpoint["generated_dns_names"] == ["a8e5b007ae34"]
    assert endpoint["gateway"] == docker_network["IPAM"]["Config"][0]["Gateway"]
    assert endpoint["backend"]["driver"] == docker_network["Driver"]
    assert endpoint["backend"]["ipam_driver"] == docker_network["IPAM"]["Driver"]
    assert endpoint["backend"]["driver_options"] == docker_network["Options"]
    assert endpoint["backend"]["ipam_options"] == {}


def test_ad_identity_authority_memberships_match_samba_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    authority = data["nodes"]["ad"]["runtime"]["identity_authorities"][0]
    subjects_by_name = {subject["name"]: subject for subject in authority["subjects"]}
    relationships = {
        (rel["source_ref"], rel["target_ref"]): rel["relationship_type"]
        for rel in authority["relationships"]
    }

    for group_name, members in _samba_group_members().items():
        group_id = subjects_by_name[group_name]["subject_id"]
        expected = {
            (subjects_by_name[member]["subject_id"], group_id)
            for member in members
            if member in subjects_by_name
        }
        actual = {
            (source_ref, target_ref)
            for (source_ref, target_ref), relationship_type in relationships.items()
            if target_ref == group_id and relationship_type == "member_of"
        }
        assert actual == expected


def test_ad_identity_subject_attributes_match_samba_user_details():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    authority = data["nodes"]["ad"]["runtime"]["identity_authorities"][0]
    subjects_by_name = {subject["name"]: subject for subject in authority["subjects"]}
    attribute_keys = {
        "sam_account_name": "sAMAccountName",
        "object_guid": "objectGUID",
        "object_sid": "objectSid",
        "user_account_control": "userAccountControl",
        "primary_group_id": "primaryGroupID",
        "last_logon": "lastLogon",
        "admin_count": "adminCount",
        "when_created": "whenCreated",
    }

    for user_name, details in _samba_user_details().items():
        if not details:
            continue
        subject = subjects_by_name[user_name]
        attributes = {
            attribute["name"]: attribute["values"]
            for attribute in subject.get("attributes", [])
        }
        for attribute_name, evidence_key in attribute_keys.items():
            if evidence_key in details:
                assert attributes[attribute_name] == [details[evidence_key]]
        # ACES rejects secret-bearing identity attribute names; keep pwdLastSet
        # in evidence, not in the SDL claim.
        assert "pwd_last_set" not in attributes


def test_techvault_sdl_parses_and_compiles_with_ad_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.ad"].spec["node"]
    runtime = node["runtime"]
    authority = runtime["identity_authorities"][0]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(node["source"]["build"]["layers"]) == AD_BUILD_HISTORY_LAYER_COUNT
    assert len(runtime["mounts"]) == AD_RUNTIME_MOUNT_COUNT
    assert len(runtime["filesystem_inventory"]) == AD_RUNTIME_FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == AD_LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == AD_LOCAL_IDENTITY_GROUP_COUNT
    assert runtime["health"]["status"] == "healthy"
    assert len(runtime["health"]["log"]) == 5
    assert len(runtime["network"]["endpoints"]) == 1
    assert runtime["network"]["published_ports"] == []
    assert len(authority["services"]) == AD_IDENTITY_AUTHORITY_SERVICE_COUNT
    assert len(authority["relationships"]) == AD_IDENTITY_AUTHORITY_RELATIONSHIP_COUNT


def test_parity_inventory_records_ad_inventory_row():
    data = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in data["rows"]}
    row = rows["scen.techvault.ad-inventory"]
    assert row["category"] == "aces_sdl"
    assert "docs/aces/inventory/ad/" in row["validation_evidence"]
    assert row["blocking_followup"] == "n/a"
