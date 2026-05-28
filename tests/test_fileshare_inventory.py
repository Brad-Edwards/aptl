"""Checks for the SCN-010 fileshare steady-state inventory bundle."""

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
FILESHARE_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "fileshare"
FILESHARE_DOC_PATH = FILESHARE_DIR / "README.md"
CAPTURE_SCRIPT_PATH = FILESHARE_DIR / "capture-evidence.sh"
LEDGER_PATH = FILESHARE_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = FILESHARE_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:4defa1d902153bd9a4c552adbf0763a5b9fa48a6bc99acad2df6c4a2fe4c7c59"
IMAGE_DIGEST = f"aptl-fileshare@{IMAGE_ID}"
PACKAGE_COUNT = 235
TRIVY_FINDING_COUNT = 120
FILESYSTEM_ENTRY_COUNT = 32
LOCAL_IDENTITY_USER_COUNT = 23
LOCAL_IDENTITY_GROUP_COUNT = 46
LEDGER_FACT_COUNT = 23

REQUIRED_EVIDENCE_FILES = {
    "capture-limits.txt",
    "captured-at-utc.txt",
    "compose-service.fileshare.json",
    "docker-compose-version.json",
    "docker-history.image.jsonl",
    "docker-history.image.txt",
    "docker-inspect.container.json",
    "docker-inspect.image.json",
    "docker-network.aptl-internal.json",
    "docker-top.txt",
    "docker-version.json",
    "docker-volume.fileshare-data.json",
    "docker-volume.fileshare-logs.json",
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
    "share-checksums.txt",
    "share-tree.txt",
    "smbclient-anonymous-probes.txt",
    "smbclient-svc-fileshare-probes.txt",
    "source-checksums.txt",
    "syft-sbom.cyclonedx.json",
    "syft-version.json",
    "trivy-sbom.cyclonedx.json",
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


def test_fileshare_inventory_note_declares_scope_and_evidence():
    text = FILESHARE_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #333",
        "aptl-fileshare",
        "custom-build",
        "non-destructive",
        "did not run",
        "aptl lab stop -v && aptl lab start",
        "Samba",
        "CAP_NET_ADMIN",
        "deploy_key",
        "mapping-ledger.yaml",
        "uv run aptl aces-inventory validate",
        "No known ACES expressivity gap remains",
        "not as clean-lab rebuild proof",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Fileshare inventory note missing scope markers: {missing}"


def test_fileshare_capture_script_pins_reproducible_toolchain_and_normalizer():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "normalize-syft-cyclonedx.jq",
        "docker-history.image.jsonl",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_fileshare_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(FILESHARE_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 333
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    assert len(ledger["correspondence_checks"]) == 2
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["fileshare.runtime.filesystem-content"] == "encoded"
    assert dispositions["fileshare.samba.share-access"] == "encoded"
    assert dispositions["fileshare.capture.toolchain-baseline"] == "encoded_with_caveat"


def test_fileshare_gap_report_surfaces_no_remaining_gaps():
    report = gap_report(FILESHARE_DIR)
    assert report["gaps"] == []
    assert not report["triage_needed"]


def test_fileshare_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [
        name
        for name in REQUIRED_EVIDENCE_FILES
        if (EVIDENCE_DIR / name).stat().st_size == 0
    ]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_fileshare_evidence_sha256_manifest_matches_files():
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


def test_fileshare_mapping_ledger_references_every_evidence_file():
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


def test_fileshare_evidence_does_not_commit_generated_secret_material():
    forbidden = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|APTL\\{|^Token:", re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
        and forbidden.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert not offenders, f"Generated secret material leaked into evidence: {offenders}"


def test_fileshare_container_runtime_state():
    container = _json_file("docker-inspect.container.json")[0]
    assert container["Name"] == "/aptl-fileshare"
    assert container["State"]["Running"] is True
    assert container["State"]["Health"]["Status"] == "healthy"
    assert container["Image"] == IMAGE_ID
    assert container["Config"]["Hostname"] == "files.techvault.local"
    assert container["HostConfig"]["Memory"] == 536870912
    assert container["HostConfig"]["CapAdd"] == ["CAP_NET_ADMIN"]
    assert container["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert "aptl_fileshare_data:/srv/shares:rw" in container["HostConfig"]["Binds"]
    assert "aptl_fileshare_logs:/var/log/samba:rw" in container["HostConfig"]["Binds"]
    assert (
        container["NetworkSettings"]["Networks"]["aptl_aptl-internal"]["IPAddress"]
        == "172.20.2.12"
    )


def test_fileshare_image_identity_and_source_package_are_recorded():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Entrypoint"] == ["/opt/setup-shares.sh"]
    assert "139/tcp" in image["Config"]["ExposedPorts"]
    assert "445/tcp" in image["Config"]["ExposedPorts"]
    assert len(image["RootFS"]["Layers"]) == 13

    source_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(
        encoding="utf-8"
    )
    for source_path in (
        "containers/fileshare/Dockerfile",
        "containers/fileshare/setup-shares.sh",
        "containers/fileshare/smb.conf",
        "containers/fileshare/supervisord.conf",
        "containers/_wazuh-agent/wazuh-agent.sh",
    ):
        assert source_path in source_checksums


def test_fileshare_runtime_baseline_captures_expected_steady_state():
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    required = (
        'VERSION="22.04.5 LTS (Jammy Jellyfish)"',
        "uid=0(root)",
        "0.0.0.0:139",
        "0.0.0.0:445",
        "/usr/bin/supervisord",
        "/usr/sbin/smbd",
        "/usr/sbin/rsyslogd",
        "/opt/aptl/wazuh/wazuh-agent.sh",
        "/srv/shares",
        "/var/log/samba",
        "CapEff:",
        "rsyslog                          RUNNING",
        "samba                            RUNNING",
        "wazuh-agent                      RUNNING",
        "svc-fileshare:x:1000:1000",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Runtime baseline missing expected observations: {missing}"


def test_fileshare_smb_access_probe_records_guest_boundaries():
    anonymous = (EVIDENCE_DIR / "smbclient-anonymous-probes.txt").read_text(
        encoding="utf-8"
    )
    svc = (EVIDENCE_DIR / "smbclient-svc-fileshare-probes.txt").read_text(
        encoding="utf-8"
    )
    assert "welcome.txt" in anonymous
    assert "wifi-passwords.txt" in anonymous
    assert anonymous.count("NT_STATUS_ACCESS_DENIED") == 4
    assert "svc-fileshare-share-list" in svc
    assert "Engineering" in svc
    assert "NT_STATUS_ACCESS_DENIED" in svc


def test_fileshare_trivy_vulnerability_summary_matches_list():
    counts = {
        item["severity"]: item["count"]
        for item in _json_file("trivy-vulnerability-counts.json")
    }
    vulnerabilities = _json_file("trivy-vulnerability-list.json")
    computed = Counter(item["severity"] for item in vulnerabilities)

    assert counts == dict(computed)
    assert sum(counts.values()) == len(vulnerabilities) == TRIVY_FINDING_COUNT
    assert counts == {"LOW": 68, "MEDIUM": 52}
    assert all(item["id"] for item in vulnerabilities)
    assert all(item["package_name"] for item in vulnerabilities)


def test_fileshare_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert trivy_sbom["metadata"]["component"]["name"].startswith("aptl-fileshare")
    assert syft_version["application"] == "syft"
    syft_location_properties = [
        prop
        for component in syft_sbom["components"]
        for prop in component.get("properties", [])
        if prop["name"].startswith("syft:location:")
    ]
    assert syft_location_properties == []


def test_fileshare_osquery_evidence_records_requested_tables_and_limits():
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
    assert {"supervisord", "rsyslogd", "smbd", "wazuh-agent.sh"} <= process_names

    listening_ports = _json_file("osquery-listening-ports.json")
    assert any(row["port"] == "139" for row in listening_ports["rows"])
    assert any(row["port"] == "445" for row in listening_ports["rows"])

    docker_containers = _json_file("osquery-docker-containers.json")
    assert docker_containers["rows"][0]["name"] == "/aptl-fileshare"

    for name in ("installed-applications", "programs"):
        payload = _json_file(f"osquery-{name}.json")
        assert payload["status"] == "unavailable"
        assert payload["rows"] == []


def test_techvault_sdl_encodes_fileshare_inventory_surfaces():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    fileshare = data["nodes"]["fileshare"]
    runtime = fileshare["runtime"]
    build = fileshare["source"]["build"]

    assert fileshare["source"]["name"] == "aptl-fileshare"
    assert fileshare["source"]["version"] == IMAGE_DIGEST
    assert build["base_image"] == "ubuntu:22.04"
    assert build["dockerfile_path"] == "containers/fileshare/Dockerfile"
    assert len(build["instructions"]) == 16
    assert len(build["layers"]) == 20
    assert len(build["source_inputs"]) == 9
    assert len(build["copied_sources"]) == 8
    assert build["config"]["entrypoint"] == ["/opt/setup-shares.sh"]
    assert {"port": 139, "protocol": "tcp", "name": "netbios-ssn"} in fileshare["services"]
    assert {"port": 445, "protocol": "tcp", "name": "microsoft-ds"} in fileshare["services"]

    mounts = {mount["target"]: mount for mount in runtime["mounts"]}
    assert mounts["/srv/shares"]["source"] == "aptl_fileshare_data"
    assert mounts["/var/log/samba"]["source"] == "aptl_fileshare_logs"
    assert mounts["/sys"]["read_only"] is True
    assert any(option.startswith("lowerdir=") for option in mounts["/"]["options"])

    assert len(runtime["packages"]) == PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert runtime["process"]["name"] == "supervisord"
    assert {process["name"] for process in runtime["processes"]} == {
        "rsyslog",
        "samba",
        "wazuh-agent",
    }
    assert runtime["linux_capabilities"]["add"] == ["CAP_NET_ADMIN"]
    assert runtime["operational_policy"]["restart"] == "unless_stopped"
    assert runtime["operational_policy"]["resource_limits"]["memory"] == 536870912
    assert runtime["health"]["status"] == "healthy"
    assert len(runtime["health"]["log"]) == 5

    file_service = runtime["file_services"][0]
    assert file_service["service_id"] == "fileshare-smb"
    assert file_service["service"] == "microsoft-ds"
    assert file_service["protocol"] == "smb"
    assert file_service["backend"] == "Samba 4.15.13-Ubuntu"

    shares = {share["share_id"]: share for share in file_service["shares"]}
    assert shares["public"]["guest_ok"] is True
    assert shares["shared"]["guest_ok"] is True
    assert shares["engineering"]["valid_groups"] == ["group-engineering"]
    assert shares["finance"]["valid_groups"] == ["group-finance"]
    assert shares["hr"]["valid_groups"] == ["group-hr"]
    assert shares["it-backups"]["browseable"] is False
    assert shares["it-backups"]["valid_groups"] == ["group-it-admins"]

    principals = {
        principal["principal_id"]: principal
        for principal in file_service["principals"]
    }
    assert principals["nobody"]["kind"] == "guest"
    assert principals["nobody"]["credential_classification"] == "no_credential"
    assert principals["svc-fileshare"]["kind"] == "service_account"
    assert principals["svc-fileshare"]["credential_classification"] == "weak"
    assert principals["svc-fileshare"]["local_user_ref"] == "svc-fileshare"

    observations = {
        observation["observation_id"]: observation
        for observation in file_service["access_observations"]
    }
    assert observations["anonymous-public-list"]["outcome"] == "allowed"
    assert observations["anonymous-engineering-list"]["outcome"] == "denied"
    assert observations["svc-fileshare-engineering-list"]["outcome"] == "denied"

    filesystem = {entry["path"]: entry for entry in runtime["filesystem_inventory"]}
    assert filesystem["/srv/shares/shared/user-flag.txt"]["sensitivity"] == "secret_fixture"
    assert filesystem["/root/root.txt"]["mode"] == "0600"
    assert filesystem["/srv/shares/it-backups/keys/deploy_key"]["entry_type"] == "file"
    assert filesystem["/srv/shares/it-backups/keys/deploy_key"]["presence"] == "expected_absent"
    assert filesystem["/srv/shares/engineering/deployments/deploy.sh"]["content_digest"] == (
        "4830319c1205cebdf51c139c0496f7e8ed27304acaafb8c4aa9b61f5bcade8e6"
    )


def test_techvault_sdl_parses_and_compiles_with_fileshare_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.fileshare"].spec["node"]
    runtime = node["runtime"]
    build = node["source"]["build"]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(build["instructions"]) == 16
    assert len(build["layers"]) == 20
    assert build["attestation"]["status"] == "absent"
    assert len(runtime["packages"]) == PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["file_services"]) == 1
    assert len(runtime["file_services"][0]["shares"]) == 6
    assert len(runtime["file_services"][0]["principals"]) == 6
    assert len(runtime["file_services"][0]["access_observations"]) == 9
    assert runtime["linux_capabilities"]["add"] == ["CAP_NET_ADMIN"]
    assert runtime["operational_policy"]["restart"] == "unless_stopped"


def test_fileshare_sdl_filesystem_inventory_matches_evidence_paths():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    encoded = {
        entry["path"]: entry
        for entry in data["nodes"]["fileshare"]["runtime"]["filesystem_inventory"]
    }
    for line in (EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines():
        path = line.split(" ", 1)[1] if line.startswith("MISSING ") else line.split(" ", 6)[6]
        assert path in encoded


def test_fileshare_runtime_local_identity_matches_passwd_and_group_evidence():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    local_identity = data["nodes"]["fileshare"]["runtime"]["local_identity"]
    encoded_users = {user["username"]: user for user in local_identity["users"]}
    encoded_groups = {group["name"]: group for group in local_identity["groups"]}

    assert len(encoded_users) == len(_runtime_baseline_section("users"))
    assert len(encoded_groups) == len(_runtime_baseline_section("groups"))
    assert encoded_users["svc-fileshare"]["uid"] == 1000
    assert encoded_users["wazuh"]["home"] == "/var/ossec"
    assert encoded_groups["sambashare"]["gid"] == 105
    assert local_identity["sudo_rules"] == []


def test_techvault_sdl_fileshare_content_accounts_relationships_and_parity():
    data = _yaml_file(TECHVAULT_SDL_PATH)
    content = data["content"]
    accounts = data["accounts"]
    relationships = data["relationships"]
    parity = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in parity["rows"]}

    assert "fileshare-file-etc-samba-smb-conf" in content
    assert content["fileshare-file-srv-shares-shared-user-flag-txt"]["sensitive"] is True
    assert "fileshare-samba-svc-fileshare" not in accounts
    assert accounts["fileshare-local-svc-fileshare"]["disabled"] is False
    assert relationships["fileshare-forwards-wazuh"]["target"] == "wazuh-manager"
    assert rows["scen.techvault.fileshare-inventory"]["category"] == "aces_sdl"
    assert rows["compose.service.fileshare"]["category"] == "aces_sdl"
