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
ACES_RUNTIME_GAP = 358
APTL_PUBLIC_HANDOFF_GAP = 321
APTL_GENERIC_REALIZER_GAP = 324

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


def test_webapp_preflight_artifact_records_local_guardrails():
    text = PREFLIGHT_PATH.read_text(encoding="utf-8")
    required = (
        "gc_codex_architecture_preflight",
        "SCN-010 / issue #330",
        "docs/aces/inventory/webapp/",
        "scenarios/techvault.sdl.yaml",
        "ACES #354",
        "#321",
        "#324",
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
        "APTL #321",
        "APTL #324",
    )
    missing = [needle for needle in required if needle not in text]
    assert not missing, f"Webapp inventory note missing scope markers: {missing}"


def test_webapp_mapping_ledger_validates_and_tracks_gap_handoff():
    result = validate_mapping_ledger(WEBAPP_DIR)
    assert result.ok, result.errors
    assert result.fact_count == 17
    assert result.encoded_count == 12
    assert result.blocked_count == 5
    assert result.triage_count == 0
    assert result.gap_issues == [
        f"ACES #{ACES_RUNTIME_GAP}",
        f"APTL #{APTL_PUBLIC_HANDOFF_GAP}",
        f"APTL #{APTL_GENERIC_REALIZER_GAP}",
    ]

    ledger = load_mapping_ledger(LEDGER_PATH)
    assert ledger["provenance"]["image_digest"] == IMAGE_DIGEST
    assert ledger["provenance"]["attestation"]["status"] == "not_available"
    assert len(ledger["correspondence_checks"]) == 3
    dispositions = {fact["id"]: fact["aces"]["disposition"] for fact in ledger["facts"]}
    assert dispositions["webapp.runtime.log-volume"] == "encoded"
    assert dispositions["webapp.runtime.supervised-process-set"] == "blocked_by_aces_gap"
    assert dispositions["webapp.aptl.public-start-handoff"] == "blocked_by_aptl_gap"
    assert dispositions["webapp.aptl.generic-realizer"] == "blocked_by_aptl_gap"


def test_webapp_gap_report_surfaces_aces_and_aptl_handoffs():
    report = gap_report(WEBAPP_DIR)
    gaps = {gap["fact_id"]: gap for gap in report["gaps"]}
    assert set(gaps) == {
        "webapp.runtime.supervised-process-set",
        "webapp.runtime.environment-policy",
        "webapp.runtime.capability-restart-policy",
        "webapp.aptl.public-start-handoff",
        "webapp.aptl.generic-realizer",
    }
    assert not report["triage_needed"]
    assert gaps["webapp.runtime.supervised-process-set"]["gap_issue"]["number"] == (
        ACES_RUNTIME_GAP
    )
    assert gaps["webapp.runtime.environment-policy"]["gap_issue"]["number"] == (
        ACES_RUNTIME_GAP
    )
    assert gaps["webapp.runtime.capability-restart-policy"]["gap_issue"]["number"] == (
        ACES_RUNTIME_GAP
    )
    assert gaps["webapp.aptl.public-start-handoff"]["gap_issue"]["number"] == (
        APTL_PUBLIC_HANDOFF_GAP
    )
    assert gaps["webapp.aptl.generic-realizer"]["gap_issue"]["number"] == (
        APTL_GENERIC_REALIZER_GAP
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

    assert data["name"] == "techvault"
    assert webapp["source"] == {"name": "aptl-webapp", "version": IMAGE_DIGEST}
    assert webapp["os"] == "linux"
    assert webapp["os_version"] == "Debian GNU/Linux 13 (trixie)"
    assert {"port": 8080, "protocol": "tcp", "name": "http"} in webapp["services"]
    assert "webapp-sqli-login" in webapp["vulnerabilities"]
    assert "webapp-command-injection" in webapp["vulnerabilities"]
    assert runtime["mounts"] == [
        {
            "target": "/var/log/gunicorn",
            "source": "aptl_webapp_logs",
            "source_kind": "volume",
            "read_only": False,
            "description": "Gunicorn access-log volume tailed by the in-process Wazuh agent.",
        }
    ]
    assert runtime["process"]["command"] == [
        "/usr/bin/python3",
        "/usr/bin/supervisord",
        "-n",
        "-c",
        "/etc/supervisor/supervisord.conf",
    ]
    package_names = {package["name"] for package in runtime["packages"]}
    assert {"python3", "supervisor", "curl", "iptables"} <= package_names
    manifest_paths = {manifest["path"] for manifest in runtime["dependency_manifests"]}
    assert "/app/requirements.txt" in manifest_paths
    assert runtime["package_vulnerabilities"]

    infrastructure = data["infrastructure"]
    assert infrastructure["webapp"]["links"] == ["dmz-net", "internal-net"]
    assert infrastructure["webapp"]["properties"] == [
        {"dmz-net": "172.20.1.20"},
        {"internal-net": "172.20.2.25"},
    ]
    assert infrastructure["webapp"]["dependencies"] == ["db", "wazuh-manager"]


def test_parity_inventory_cites_webapp_inventory_and_aces_sdl():
    inventory = _yaml_file(PARITY_PATH)
    rows = {row["id"]: row for row in inventory["rows"]}

    assert rows["scen.techvault.webapp-inventory"]["legacy_source"] == (
        "scenarios/techvault.sdl.yaml"
    )
    assert rows["scen.techvault.webapp-inventory"]["category"] == "aces_sdl"
    assert "docs/aces/inventory/webapp/" in rows["scen.techvault.webapp-inventory"][
        "validation_evidence"
    ]

    assert rows["compose.service.webapp"]["legacy_source"] == (
        "docker-compose.yml (service: webapp)"
    )
    assert rows["compose.service.webapp"]["category"] == "aces_sdl"
    assert "nodes.webapp" in rows["compose.service.webapp"]["aces_target"]
