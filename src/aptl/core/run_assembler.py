"""Run assembly orchestrator.

Collects all experiment data from various sources and writes it to
a structured run directory via the storage backend.
"""

import os
from datetime import datetime, timezone
from pathlib import Path

from aptl.core.collectors import (
    collect_container_logs,
    collect_misp_events,
    collect_shuffle_executions,
    collect_suricata_eve,
    collect_thehive_cases,
    collect_traces,
    collect_wazuh_alerts,
)
from aptl.core.config import AptlConfig
from aptl.core.runstore import LocalRunStore, RunManifest
from aptl.core.scenarios import ScenarioDefinition
from aptl.core.session import ActiveSession
from aptl.core.snapshot import capture_snapshot
from aptl.utils.logging import get_logger

log = get_logger("run_assembler")


def _active_containers() -> list[str]:
    """List running Docker containers with the aptl- prefix."""
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}", "--filter", "name=aptl-"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return [n.strip() for n in result.stdout.splitlines() if n.strip()]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return []


def assemble_run(
    store: LocalRunStore,
    run_id: str,
    session: ActiveSession,
    scenario: ScenarioDefinition,
    scenario_path: Path,
    config: AptlConfig,
) -> Path:
    """Assemble a complete run directory after scenario stop.

    Collects data from all sources and writes it to the run store.
    Each collector is fault-tolerant — failures are logged but do
    not prevent the rest of the assembly from completing.

    Returns:
        Path to the run directory.
    """
    finished_at = datetime.now(timezone.utc).isoformat()
    started_at = session.started_at

    # 1. Create run directory
    run_dir = store.create_run(run_id)
    log.info("Assembling run %s at %s", run_id, run_dir)

    # 1b. Capture range snapshot
    try:
        snapshot = capture_snapshot(config_dir=scenario_path.parent)
        store.write_json(run_id, "snapshot.json", snapshot.to_dict())
    except Exception:
        log.exception("Failed to capture range snapshot")

    # 2. Write flags
    store.write_json(run_id, "flags.json", session.flags)

    # 3. Copy scenario YAML
    if scenario_path.exists():
        store.copy_file(run_id, "scenario/definition.yaml", scenario_path)

    # 4. Collect Wazuh alerts
    indexer_url = os.getenv("APTL_INDEXER_URL", "https://localhost:9200")
    indexer_user = os.getenv("INDEXER_USERNAME", "admin")
    indexer_pass = os.getenv("INDEXER_PASSWORD", "")
    alerts = collect_wazuh_alerts(
        started_at, finished_at,
        indexer_url=indexer_url,
        auth=(indexer_user, indexer_pass) if indexer_pass else None,
    )
    store.write_jsonl(run_id, "wazuh/alerts.jsonl", alerts)

    # 5. Collect Suricata EVE
    eve_entries = collect_suricata_eve(started_at, finished_at)
    if eve_entries:
        store.write_jsonl(run_id, "suricata/eve.jsonl", eve_entries)

    # 6. Collect TheHive cases
    thehive_url = os.getenv("THEHIVE_URL", "http://localhost:9000")
    thehive_key = os.getenv("THEHIVE_API_KEY", "")
    cases = collect_thehive_cases(
        started_at, finished_at, url=thehive_url, api_key=thehive_key
    )
    if cases:
        store.write_json(run_id, "soc/thehive-cases.json", cases)

    # 7. Collect MISP correlations
    misp_url = os.getenv("MISP_URL", "https://localhost:8443")
    misp_key = os.getenv("MISP_API_KEY", "")
    misp_events = collect_misp_events(
        started_at, finished_at, url=misp_url, api_key=misp_key
    )
    if misp_events:
        store.write_json(run_id, "soc/misp-correlations.json", misp_events)

    # 8. Collect Shuffle executions
    shuffle_url = os.getenv("SHUFFLE_URL", "http://localhost:5001")
    shuffle_key = os.getenv("SHUFFLE_API_KEY", "")
    shuffle_execs = collect_shuffle_executions(
        started_at, finished_at, url=shuffle_url, api_key=shuffle_key
    )
    if shuffle_execs:
        store.write_json(run_id, "soc/shuffle-executions.json", shuffle_execs)

    # 9. Collect container logs
    containers = _active_containers()
    container_logs = collect_container_logs(containers, started_at, finished_at)
    for name, log_text in container_logs.items():
        store.write_file(
            run_id, f"containers/{name}.log", log_text.encode("utf-8")
        )

    # 10. Collect traces from Tempo
    spans: list[dict] = []
    if session.trace_id:
        spans = collect_traces(session.trace_id)
        if spans:
            store.write_json(run_id, "traces/spans.json", spans)

    # 11. Write manifest
    started_dt = datetime.fromisoformat(started_at)
    finished_dt = datetime.fromisoformat(finished_at)
    duration = (finished_dt - started_dt).total_seconds()

    manifest: RunManifest = {
        "run_id": run_id,
        "scenario_id": scenario.metadata.id,
        "scenario_name": scenario.metadata.name,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "trace_id": session.trace_id,
        "config_snapshot": {
            "lab": config.lab.model_dump(),
            "containers": config.containers.model_dump(),
        },
        "containers": containers,
        "flags_captured": sum(len(v) for v in session.flags.values()),
    }
    store.write_json(run_id, "manifest.json", manifest)

    log.info(
        "Run %s assembled: %d alerts, %d spans, %d container logs",
        run_id,
        len(alerts),
        len(spans),
        len(container_logs),
    )
    return run_dir
