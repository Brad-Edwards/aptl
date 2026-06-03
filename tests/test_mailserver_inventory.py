"""Checks for the SCN-010 mailserver steady-state inventory bundle."""

from pathlib import Path
import gzip
import hashlib
import json
import re

import yaml

from tests.techvault_sdl import load_legacy_techvault_sdl

from aptl.core.aces_inventory import (
    gap_report,
    load_mapping_ledger,
    validate_mapping_ledger,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAILSERVER_DIR = PROJECT_ROOT / "docs" / "aces" / "inventory" / "mailserver"
MAILSERVER_DOC_PATH = MAILSERVER_DIR / "README.md"
CAPTURE_SCRIPT_PATH = MAILSERVER_DIR / "capture-evidence.sh"
LEDGER_PATH = MAILSERVER_DIR / "mapping-ledger.yaml"
EVIDENCE_DIR = MAILSERVER_DIR / "evidence"
TECHVAULT_SDL_PATH = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
PARITY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

IMAGE_ID = "sha256:af51b15dd3fc72153c0e90eb7692bb5e3a463212d87959a80fa7aa89b617d44a"
IMAGE_DIGEST = "ghcr.io/docker-mailserver/docker-mailserver@sha256:af51b15dd3fc72153c0e90eb7692bb5e3a463212d87959a80fa7aa89b617d44a"
MAILBOX_COUNT = 10
RUNTIME_PACKAGE_COUNT = 395
TRIVY_FINDING_COUNT = 1415
FILESYSTEM_ENTRY_COUNT = 177
LOCAL_IDENTITY_USER_COUNT = 35
LOCAL_IDENTITY_GROUP_COUNT = 56
MAIL_SETTING_COUNT = 156
LEDGER_FACT_COUNT = 21
BUILD_HISTORY_LAYER_COUNT = 86
SOURCE_INPUT_COUNT = 2

REQUIRED_EVIDENCE_FILES = {'docker-top.txt', 'os-packages.txt', 'trivy-version.txt', 'docker-inspect.image.json', 'language-manifests.txt', 'docker-compose-version.json', 'docker-history.image.txt', 'osquery-installed-applications.json', 'docker-history.image.jsonl', 'trivy-vulnerability-list.json', 'mailserver-state.txt', 'participant-discovery.kali.txt', 'trivy-vulnerability-counts.json', 'captured-at-utc.txt', 'filesystem-tree.txt', 'compose-service.mailserver.json', 'docker-inspect.container.json', 'filesystem-checksums.txt', 'source-checksums.txt', 'docker-buildx-imagetools.image.txt', 'docker-network.aptl-dmz.json', 'osquery-programs.json', 'docker-network.aptl-internal.json', 'osquery-docker-images.json', 'docker-logs.mailserver.txt', 'docker-version.json', 'docker-volume.mailserver-state.json', 'runtime-baseline.txt', 'osquery-apt-sources.json', 'syft-sbom.cyclonedx.json.gz', 'osquery-processes.json', 'syft-version.json', 'evidence-sha256sums.txt', 'docker-volume.mailserver-data.json', 'docker-volume.mailserver-logs.json', 'docker-buildx-imagetools.image.raw.json', 'osquery-version.txt', 'osquery-docker-containers.json', 'osquery-listening-ports.json', 'trivy-sbom.cyclonedx.json.gz', 'capture-limits.txt'}

RAW_SECRET_PATTERNS = (
    r"TvMail2024!",
    r"BEGIN .*PRIVATE KEY",
    r"APTL\{",
)


def _json_file(name: str):
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, mode="rt", encoding="utf-8") as fh:
        return json.load(fh)


def _evidence_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8", errors="ignore")


def _yaml_file(path: Path):
    if path == TECHVAULT_SDL_PATH:
        return load_legacy_techvault_sdl(str(path))
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_mailserver_inventory_note_declares_scope_and_realization_caveats():
    text = MAILSERVER_DOC_PATH.read_text(encoding="utf-8")
    required = (
        "SCN-010",
        "issue #335",
        "aptl-mailserver",
        "docker-mailserver",
        "non-destructive",
        "did not run",
        "manual",
        "TCP 993 is host-published but refused",
        "TCP 465 is reachable but implicit TLS probe fails",
        "ACES issue #420 / ADR-038",
        "No known ACES expressivity gap remains",
        "shell-equivalent `$EC`",
        "not as clean-lab rebuild proof",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Mailserver inventory note missing scope markers: {missing}"


def test_mailserver_capture_script_pins_reproducible_toolchain_and_protocol_probes():
    text = CAPTURE_SCRIPT_PATH.read_text(encoding="utf-8")
    required = (
        "aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
        "anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
        "osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd",
        "docker-history.image.jsonl",
        "participant-discovery.kali.txt",
        "openssl s_client -connect 172.20.1.21:465",
        "openssl s_client -connect 172.20.1.21:993",
        "evidence-sha256sums.txt",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Capture script missing reproducibility markers: {missing}"
    assert CAPTURE_SCRIPT_PATH.stat().st_mode & 0o111


def test_mailserver_mapping_ledger_validates_without_gaps():
    result = validate_mapping_ledger(MAILSERVER_DIR)
    assert result.ok, result.errors
    assert result.fact_count == LEDGER_FACT_COUNT
    assert result.encoded_count == LEDGER_FACT_COUNT
    assert result.blocked_count == 0
    assert result.triage_count == 0
    assert result.gap_issues == []

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["asset"]["aptl_issue"] == 335
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["mailserver.mail.protocol-capabilities"] == "encoded"
    assert dispositions["mailserver.mail.runtime-settings"] == "encoded"
    assert dispositions["mailserver.capture.toolchain-baseline"] == "encoded_with_caveat"


def test_mailserver_gap_report_has_no_remaining_aces_gaps():
    report = gap_report(MAILSERVER_DIR)
    assert report["gaps"] == []
    assert report["triage_needed"] == []


def test_mailserver_evidence_bundle_files_are_present_and_non_empty():
    present = {path.name for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert REQUIRED_EVIDENCE_FILES <= present
    empty = [name for name in REQUIRED_EVIDENCE_FILES if (EVIDENCE_DIR / name).stat().st_size == 0]
    assert not empty, f"Evidence files must not be empty: {empty}"


def test_mailserver_evidence_sha256_manifest_matches_files():
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


def test_mailserver_mapping_ledger_references_every_evidence_file():
    ledger = load_mapping_ledger(LEDGER_PATH)
    refs = set()
    refs.update(ref["path"] for ref in ledger["provenance"]["attestation"].get("evidence", []))
    for check in ledger["correspondence_checks"]:
        refs.update(ref["path"] for ref in check.get("realized_evidence", []))
    for fact in ledger["facts"]:
        refs.update(ref["path"] for ref in fact["evidence"])

    evidence_files = {f"evidence/{path.name}" for path in EVIDENCE_DIR.iterdir() if path.is_file()}
    assert evidence_files <= refs


def test_mailserver_evidence_does_not_commit_raw_secret_values():
    forbidden = re.compile("|".join(RAW_SECRET_PATTERNS), re.MULTILINE)
    offenders = [
        path.name
        for path in EVIDENCE_DIR.iterdir()
        if path.is_file()
        and path.name not in {"filesystem-checksums.txt", "evidence-sha256sums.txt"}
        and forbidden.search(_evidence_text(path))
    ]
    assert not offenders, f"Raw secret material leaked into evidence: {offenders}"


def test_mailserver_runtime_evidence_counts_and_caveats():
    image = _json_file("docker-inspect.image.json")[0]
    assert image["Id"] == IMAGE_ID
    assert IMAGE_DIGEST in image["RepoDigests"]
    assert image["Config"]["Labels"]["org.opencontainers.image.version"] == "v15.1.0"

    assert len((EVIDENCE_DIR / "os-packages.txt").read_text(encoding="utf-8").splitlines()) == RUNTIME_PACKAGE_COUNT
    assert len(_json_file("trivy-vulnerability-list.json")) == TRIVY_FINDING_COUNT
    assert len((EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines()) == FILESYSTEM_ENTRY_COUNT

    participant = (EVIDENCE_DIR / "participant-discovery.kali.txt").read_text(encoding="utf-8")
    assert "25 (smtp) open" in participant
    assert "143 (imap2) open" in participant
    assert "465 (submissions) open" in participant
    assert "993 (imaps) : Connection refused" in participant
    assert "wrong version number" in participant


def test_mailserver_sbom_toolchain_evidence_is_cyclonedx():
    trivy_sbom = _json_file("trivy-sbom.cyclonedx.json.gz")
    syft_sbom = _json_file("syft-sbom.cyclonedx.json.gz")
    syft_version = _json_file("syft-version.json")

    assert trivy_sbom["bomFormat"] == "CycloneDX"
    assert syft_sbom["bomFormat"] == "CycloneDX"
    assert trivy_sbom["components"]
    assert syft_sbom["components"]
    assert syft_version["application"] == "syft"


def test_techvault_sdl_encodes_mailserver_inventory_surfaces():
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    node = scenario.nodes["techvault.mailserver"]
    assert node.source.version == IMAGE_DIGEST
    assert node.os_version == "Debian GNU/Linux 12 (bookworm)"

    services = {service.name: service.port for service in node.services}
    assert services == {"smtp": 25, "imap": 143, "smtps": 465, "submission": 587}

    runtime = node.runtime
    assert runtime is not None
    assert len(runtime.packages) == RUNTIME_PACKAGE_COUNT
    assert len(runtime.package_vulnerabilities) == TRIVY_FINDING_COUNT
    assert len(runtime.filesystem_inventory) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime.local_identity.users) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime.local_identity.groups) == LOCAL_IDENTITY_GROUP_COUNT

    published = {port.container_port: port.host_port for port in runtime.network.published_ports}
    assert published == {25: 25, 143: 143, 587: 587, 993: 993}

    mail_service = runtime.mail_services[0]
    assert mail_service.mail_service_id == "techvault-mail"
    assert mail_service.engine == "docker-mailserver"
    assert len(mail_service.mailboxes) == MAILBOX_COUNT
    assert len(mail_service.settings) == MAIL_SETTING_COUNT
    assert mail_service.aliases == []
    assert mail_service.queues[0].message_count == 0

    listeners = {listener.listener_id: listener for listener in mail_service.listeners}
    assert set(listeners) == {"smtp-25", "submission-587", "smtp-465-plaintext", "imap-143"}
    assert listeners["submission-587"].auth_mechanisms == ["plain", "login"]
    assert listeners["smtp-465-plaintext"].tls_mode == "none"
    assert "AUTH=LOGIN" in listeners["imap-143"].capabilities

    relationships = scenario.relationships
    smtp_probe = relationships["techvault.kali-probes-mailserver-smtp"]
    assert smtp_probe.target == "nodes.techvault.mailserver.runtime.mail_services.techvault-mail.listeners.smtp-25"
    assert smtp_probe.mail_access.listener_ref == "smtp-25"
    assert smtp_probe.mail_access.protocol == "smtp"


def test_techvault_sdl_parses_and_compiles_with_mailserver_runtime_fields():
    from aces_processor.compiler import compile_runtime_model
    from aces_sdl import parse_sdl_file

    scenario = parse_sdl_file(TECHVAULT_SDL_PATH)
    model = compile_runtime_model(scenario)
    node = model.node_deployments["provision.node.techvault.mailserver"].spec["node"]
    runtime = node["runtime"]
    build = node["source"]["build"]
    mail_service = runtime["mail_services"][0]

    assert node["source"]["version"] == IMAGE_DIGEST
    assert len(build["instructions"]) == BUILD_HISTORY_LAYER_COUNT
    assert len(build["layers"]) == BUILD_HISTORY_LAYER_COUNT
    assert len(build["source_inputs"]) == SOURCE_INPUT_COUNT
    assert build["attestation"]["status"] == "absent"
    assert len(runtime["packages"]) == RUNTIME_PACKAGE_COUNT
    assert len(runtime["package_vulnerabilities"]) == TRIVY_FINDING_COUNT
    assert len(runtime["filesystem_inventory"]) == FILESYSTEM_ENTRY_COUNT
    assert len(runtime["local_identity"]["users"]) == LOCAL_IDENTITY_USER_COUNT
    assert len(runtime["local_identity"]["groups"]) == LOCAL_IDENTITY_GROUP_COUNT
    assert len(runtime["network"]["endpoints"]) == 2
    assert len(runtime["network"]["published_ports"]) == 4
    assert runtime["container"]["runtime_name"] == "runc"
    assert mail_service["mail_service_id"] == "techvault-mail"
    assert mail_service["engine"] == "docker-mailserver"
    assert len(mail_service["listeners"]) == 4
    assert len(mail_service["mailboxes"]) == MAILBOX_COUNT
    assert len(mail_service["settings"]) == MAIL_SETTING_COUNT
    assert mail_service["queues"][0]["message_count"] == 0


def test_parity_inventory_cites_mailserver_inventory_and_aces_sdl():
    rows = {row["id"]: row for row in _yaml_file(PARITY_PATH)["rows"]}
    row = rows["scen.techvault.mailserver-inventory"]
    assert row["category"] == "aces_sdl"
    assert "nodes.techvault.mailserver.runtime.mail_services" in row["aces_target"]
    assert "tests/test_mailserver_inventory.py" in row["validation_evidence"]
    assert row["blocking_followup"] == "n/a"
