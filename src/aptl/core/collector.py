"""Data collection for experiment runs.

Gathers artefacts from multiple sources and writes them into the
experiment directory:
  - Container logs (via docker compose logs)
  - Wazuh alerts (via OpenSearch query for the run time window)
  - Event timeline (copy from .aptl/events/)
  - Scenario report (copy from .aptl/reports/)
  - Wazuh manager active-response logs
  - CLI activity log
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aptl.utils.logging import get_logger

log = get_logger("collector")


# ---------------------------------------------------------------------------
# Container logs
# ---------------------------------------------------------------------------


def collect_container_logs(
    exp_dir: Path,
    *,
    since: str = "",
    until: str = "",
    services: list[str] | None = None,
    project_dir: Path | None = None,
) -> list[Path]:
    """Collect logs from Docker Compose services into the experiment directory.

    Uses ``docker compose logs`` with optional time bounds.

    Args:
        exp_dir: Experiment directory root.
        since: Timestamp or duration to start collecting from (e.g. the run start).
        until: Timestamp or duration to stop collecting at.
        services: Specific services to collect. None collects all.
        project_dir: Working directory for docker compose.

    Returns:
        List of paths to written log files.
    """
    logs_dir = exp_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    # Determine which services to collect
    if services is None:
        services = _list_compose_services(project_dir)

    for service in services:
        cmd = ["docker", "compose", "logs", "--no-color"]
        if since:
            cmd.extend(["--since", since])
        if until:
            cmd.extend(["--until", until])
        cmd.append(service)

        kwargs: dict[str, Any] = {"capture_output": True, "text": True, "timeout": 60}
        if project_dir is not None:
            kwargs["cwd"] = project_dir

        try:
            result = subprocess.run(cmd, **kwargs)
            if result.stdout.strip():
                log_path = logs_dir / f"{service}.log"
                log_path.write_text(result.stdout, encoding="utf-8")
                written.append(log_path)
                log.info("Collected %d bytes of logs for %s", len(result.stdout), service)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
            log.warning("Failed to collect logs for %s: %s", service, e)

    # Also collect the combined log
    cmd = ["docker", "compose", "logs", "--no-color"]
    if since:
        cmd.extend(["--since", since])
    if until:
        cmd.extend(["--until", until])

    kwargs = {"capture_output": True, "text": True, "timeout": 120}
    if project_dir is not None:
        kwargs["cwd"] = project_dir

    try:
        result = subprocess.run(cmd, **kwargs)
        if result.stdout.strip():
            combined_path = logs_dir / "combined.log"
            combined_path.write_text(result.stdout, encoding="utf-8")
            written.append(combined_path)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning("Failed to collect combined logs: %s", e)

    return written


def _list_compose_services(project_dir: Path | None = None) -> list[str]:
    """List all docker compose service names."""
    cmd = ["docker", "compose", "config", "--services"]
    kwargs: dict[str, Any] = {"capture_output": True, "text": True, "timeout": 30}
    if project_dir is not None:
        kwargs["cwd"] = project_dir

    try:
        result = subprocess.run(cmd, **kwargs)
        if result.returncode == 0:
            return [s.strip() for s in result.stdout.splitlines() if s.strip()]
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return []


# ---------------------------------------------------------------------------
# Wazuh alerts
# ---------------------------------------------------------------------------


def collect_wazuh_alerts(
    exp_dir: Path,
    *,
    start_time: str,
    end_time: str = "",
    indexer_url: str = "https://localhost:9200",
    username: str = "admin",
    password: str = "SecretPassword",
    index_pattern: str = "wazuh-alerts-4.x-*",
    max_alerts: int = 10000,
) -> Path | None:
    """Collect all Wazuh alerts generated during the experiment run.

    Queries the Wazuh Indexer (OpenSearch) for alerts between start_time
    and end_time, writing them to alerts/wazuh_alerts.json.

    Args:
        exp_dir: Experiment directory root.
        start_time: ISO 8601 start of the collection window.
        end_time: ISO 8601 end. Defaults to now.
        indexer_url: Wazuh Indexer URL.
        username: Basic auth username.
        password: Basic auth password.
        index_pattern: OpenSearch index pattern.
        max_alerts: Maximum alerts to collect.

    Returns:
        Path to the alerts file, or None on failure.
    """
    import base64
    import ssl
    import urllib.error
    import urllib.request

    if not end_time:
        end_time = datetime.now(timezone.utc).isoformat()

    alerts_dir = exp_dir / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    alerts_path = alerts_dir / "wazuh_alerts.json"

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time,
                                "format": "strict_date_optional_time",
                            }
                        }
                    }
                ]
            }
        },
        "size": max_alerts,
        "sort": [{"timestamp": {"order": "asc"}}],
    }

    url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
    body = json.dumps(query).encode("utf-8")

    credentials = f"{username}:{password}"
    auth_header = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": auth_header,
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        log.warning("Failed to collect Wazuh alerts: %s", e)
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("Invalid JSON from Wazuh Indexer: %s", e)
        return None

    hits = data.get("hits", {})
    total = hits.get("total", {})
    total_value = total.get("value", 0) if isinstance(total, dict) else total
    sources = [hit["_source"] for hit in hits.get("hits", []) if "_source" in hit]

    alert_data = {
        "collection_metadata": {
            "start_time": start_time,
            "end_time": end_time,
            "index_pattern": index_pattern,
            "total_available": total_value,
            "collected_count": len(sources),
            "max_alerts": max_alerts,
        },
        "alerts": sources,
    }

    alerts_path.write_text(
        json.dumps(alert_data, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    log.info("Collected %d Wazuh alerts to %s", len(sources), alerts_path)
    return alerts_path


# ---------------------------------------------------------------------------
# Event timeline
# ---------------------------------------------------------------------------


def collect_events(
    exp_dir: Path,
    state_dir: Path,
    events_file: str,
) -> Path | None:
    """Copy the scenario event timeline into the experiment directory.

    Args:
        exp_dir: Experiment directory root.
        state_dir: The .aptl/ state directory.
        events_file: Relative path to the events JSONL file from state_dir.

    Returns:
        Path to the copied events file, or None if source not found.
    """
    src = state_dir / events_file
    if not src.exists():
        log.warning("Events file not found: %s", src)
        return None

    dest = exp_dir / "events" / "timeline.jsonl"
    shutil.copy2(src, dest)
    log.info("Collected events timeline to %s", dest)
    return dest


# ---------------------------------------------------------------------------
# Scenario report
# ---------------------------------------------------------------------------


def collect_report(
    exp_dir: Path,
    report_path: Path,
) -> Path | None:
    """Copy a scenario report into the experiment directory.

    Args:
        exp_dir: Experiment directory root.
        report_path: Path to the scenario report JSON.

    Returns:
        Path to the copied report, or None if source not found.
    """
    if not report_path.exists():
        log.warning("Report file not found: %s", report_path)
        return None

    dest = exp_dir / "report" / report_path.name
    shutil.copy2(report_path, dest)
    log.info("Collected report to %s", dest)
    return dest


def find_latest_report(state_dir: Path, scenario_id: str) -> Path | None:
    """Find the most recent report for a scenario.

    Args:
        state_dir: The .aptl/ state directory.
        scenario_id: Scenario identifier.

    Returns:
        Path to the latest report, or None if no reports found.
    """
    reports_dir = state_dir / "reports"
    if not reports_dir.exists():
        return None

    candidates = sorted(
        reports_dir.glob(f"{scenario_id}_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Wazuh manager artefacts
# ---------------------------------------------------------------------------


def collect_wazuh_active_responses(exp_dir: Path) -> Path | None:
    """Collect active response logs from the Wazuh manager.

    Returns:
        Path to the collected log, or None on failure.
    """
    manager = "aptl-wazuh.manager-1"

    try:
        result = subprocess.run(
            [
                "docker", "exec", manager, "sh", "-c",
                "cat /var/ossec/logs/active-responses.log 2>/dev/null || echo ''",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            dest = exp_dir / "logs" / "wazuh_active_responses.log"
            dest.write_text(result.stdout, encoding="utf-8")
            return dest
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning("Failed to collect active response log: %s", e)

    return None


def collect_wazuh_archives(exp_dir: Path) -> Path | None:
    """Collect the Wazuh archive log (all events)."""
    manager = "aptl-wazuh.manager-1"

    try:
        result = subprocess.run(
            [
                "docker", "exec", manager, "sh", "-c",
                "cat /var/ossec/logs/archives/archives.json 2>/dev/null || echo ''",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            dest = exp_dir / "logs" / "wazuh_archives.json"
            dest.write_text(result.stdout, encoding="utf-8")
            return dest
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning("Failed to collect archive log: %s", e)

    return None


def collect_wazuh_alerts_log(exp_dir: Path) -> Path | None:
    """Collect the Wazuh alerts log file (JSON format)."""
    manager = "aptl-wazuh.manager-1"

    try:
        result = subprocess.run(
            [
                "docker", "exec", manager, "sh", "-c",
                "cat /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo ''",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            dest = exp_dir / "logs" / "wazuh_alerts_file.json"
            dest.write_text(result.stdout, encoding="utf-8")
            return dest
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning("Failed to collect alerts log file: %s", e)

    return None


# ---------------------------------------------------------------------------
# Kali activity log
# ---------------------------------------------------------------------------


def collect_kali_activity(exp_dir: Path) -> Path | None:
    """Collect the Kali red team activity log."""
    try:
        result = subprocess.run(
            [
                "docker", "exec", "aptl-kali-1", "sh", "-c",
                "cat /home/kali/operations/activity.log 2>/dev/null || echo ''",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            dest = exp_dir / "logs" / "kali_activity.log"
            dest.write_text(result.stdout, encoding="utf-8")
            return dest
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning("Failed to collect Kali activity log: %s", e)

    return None


# ---------------------------------------------------------------------------
# Bash history from containers
# ---------------------------------------------------------------------------


def collect_shell_histories(exp_dir: Path) -> list[Path]:
    """Collect bash history from key containers."""
    collected: list[Path] = []
    targets = [
        ("aptl-kali-1", "/home/kali/.bash_history", "kali_bash_history.txt"),
        ("aptl-victim-1", "/home/labadmin/.bash_history", "victim_bash_history.txt"),
        ("aptl-victim-1", "/root/.bash_history", "victim_root_bash_history.txt"),
    ]

    for container, hist_path, filename in targets:
        try:
            result = subprocess.run(
                ["docker", "exec", container, "cat", hist_path],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                dest = exp_dir / "logs" / filename
                dest.write_text(result.stdout, encoding="utf-8")
                collected.append(dest)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass

    return collected


# ---------------------------------------------------------------------------
# Full collection orchestrator
# ---------------------------------------------------------------------------


def collect_all(
    exp_dir: Path,
    *,
    state_dir: Path,
    project_dir: Path,
    scenario_id: str,
    start_time: str,
    end_time: str = "",
    events_file: str = "",
) -> dict[str, Any]:
    """Run all collectors and return a summary of what was collected.

    Args:
        exp_dir: Experiment directory root.
        state_dir: The .aptl/ state directory.
        project_dir: Root of the APTL project.
        scenario_id: Active scenario ID.
        start_time: ISO 8601 start time of the experiment.
        end_time: ISO 8601 end time (defaults to now).
        events_file: Relative path to the events JSONL file.

    Returns:
        Dict mapping collector names to their output paths or status.
    """
    if not end_time:
        end_time = datetime.now(timezone.utc).isoformat()

    summary: dict[str, Any] = {"collected_at": end_time, "artefacts": {}}

    # Container logs
    log_paths = collect_container_logs(
        exp_dir, since=start_time, until=end_time, project_dir=project_dir,
    )
    summary["artefacts"]["container_logs"] = [str(p) for p in log_paths]

    # Wazuh alerts from indexer
    alert_path = collect_wazuh_alerts(
        exp_dir, start_time=start_time, end_time=end_time,
    )
    summary["artefacts"]["wazuh_alerts"] = str(alert_path) if alert_path else None

    # Event timeline
    if events_file:
        events_path = collect_events(exp_dir, state_dir, events_file)
        summary["artefacts"]["events"] = str(events_path) if events_path else None

    # Scenario report
    report_path = find_latest_report(state_dir, scenario_id)
    if report_path:
        collected_report = collect_report(exp_dir, report_path)
        summary["artefacts"]["report"] = str(collected_report) if collected_report else None

    # Wazuh artefacts
    ar_path = collect_wazuh_active_responses(exp_dir)
    summary["artefacts"]["active_responses"] = str(ar_path) if ar_path else None

    archive_path = collect_wazuh_archives(exp_dir)
    summary["artefacts"]["wazuh_archives"] = str(archive_path) if archive_path else None

    alerts_log = collect_wazuh_alerts_log(exp_dir)
    summary["artefacts"]["wazuh_alerts_log"] = str(alerts_log) if alerts_log else None

    # Kali activity
    kali_path = collect_kali_activity(exp_dir)
    summary["artefacts"]["kali_activity"] = str(kali_path) if kali_path else None

    # Shell histories
    histories = collect_shell_histories(exp_dir)
    summary["artefacts"]["shell_histories"] = [str(p) for p in histories]

    # Write collection summary
    summary_path = exp_dir / "collection_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    total = sum(
        1 for v in summary["artefacts"].values()
        if v is not None and v != [] and v != "None"
    )
    log.info("Collection complete: %d artefact groups collected", total)

    return summary
