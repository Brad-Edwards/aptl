"""Data collectors for experiment runs.

Each collector gathers data from one source (Wazuh, Suricata, TheHive,
MISP, Shuffle, Docker containers, MCP traces) and returns structured
results. All collectors are fault-tolerant: they return empty results
when a service is unavailable and never raise.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.curl_safe import curl_json as _curl_json
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment import DeploymentBackend

log = get_logger("collectors")

# 120s timeout for SOC-tool collection calls — these scrape large
# windows of historical data (Wazuh scroll, MISP rest-search, TheHive
# query) and the default 30s is too aggressive. Pass this constant
# explicitly at every call site so the choice is visible.
_COLLECTOR_HTTP_TIMEOUT = 120


def _run_cmd(
    cmd: list[str], timeout: int = 30
) -> subprocess.CompletedProcess | None:
    """Run a command, returning None on failure."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("Command failed: %s: %s", " ".join(cmd[:3]), e)
        return None


def collect_wazuh_alerts(
    start_iso: str,
    end_iso: str,
    indexer_url: str = "https://localhost:9200",
    auth: tuple[str, str] = ("admin", "SecretPassword"),
) -> list[dict]:
    """Query Wazuh Indexer for all alerts in the time window.

    Uses scroll API for pagination (1000 docs/page).
    """
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_iso,
                    "lte": end_iso,
                }
            }
        },
        "size": 1000,
        "sort": [{"@timestamp": "asc"}],
    }

    all_hits: list[dict] = []
    scroll_id = None

    try:
        # Initial search with scroll
        url = f"{indexer_url}/wazuh-alerts-4.x-*/_search?scroll=2m"
        data = _curl_json(
            url,
            auth=auth,
            body=query,
            insecure=True,
            timeout=_COLLECTOR_HTTP_TIMEOUT,
        )
        if data is None:
            log.warning("Failed to query Wazuh Indexer for alerts")
            return []

        hits = data.get("hits", {}).get("hits", [])
        all_hits.extend(h.get("_source", h) for h in hits)
        scroll_id = data.get("_scroll_id")

        # Scroll through remaining pages
        while scroll_id and len(hits) == 1000:
            scroll_body = {"scroll": "2m", "scroll_id": scroll_id}
            scroll_url = f"{indexer_url}/_search/scroll"
            data = _curl_json(
                scroll_url,
                auth=auth,
                body=scroll_body,
                insecure=True,
                timeout=_COLLECTOR_HTTP_TIMEOUT,
            )
            if data is None:
                break
            hits = data.get("hits", {}).get("hits", [])
            all_hits.extend(h.get("_source", h) for h in hits)
            scroll_id = data.get("_scroll_id")

    except Exception as e:
        log.warning("Error collecting Wazuh alerts: %s", e)

    log.info("Collected %d Wazuh alerts", len(all_hits))
    return all_hits


def collect_suricata_eve(
    start_iso: str,
    end_iso: str,
    backend: "DeploymentBackend",
) -> list[dict]:
    """Read Suricata EVE JSON entries from the suricata container."""
    try:
        result = backend.container_exec(
            "aptl-suricata",
            ["cat", "/var/log/suricata/eve.json"],
            timeout=30,
        )
    except (BackendTimeoutError, OSError) as e:
        log.warning("Suricata EVE collection failed: %s", e)
        return []
    if result.returncode != 0:
        log.info("Suricata container not available, skipping EVE collection")
        return []

    start_dt = datetime.fromisoformat(start_iso)
    end_dt = datetime.fromisoformat(end_iso)
    records = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = entry.get("timestamp", "")
        if ts:
            try:
                entry_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if start_dt <= entry_dt <= end_dt:
                    records.append(entry)
            except ValueError:
                continue

    log.info("Collected %d Suricata EVE entries", len(records))
    return records


def collect_thehive_cases(
    start_iso: str,
    end_iso: str,
    url: str = "http://localhost:9000",
    api_key: str = "",
) -> list[dict]:
    """Query TheHive API for cases/alerts created during the run."""
    if not api_key:
        log.info("No TheHive API key, skipping case collection")
        return []

    query_body = {
        "query": [
            {
                "_name": "listCase",
            },
            {
                "_name": "filter",
                "_and": [
                    {"_gte": {"_field": "_createdAt", "_value": start_iso}},
                    {"_lte": {"_field": "_createdAt", "_value": end_iso}},
                ],
            },
        ],
    }

    data = _curl_json(
        f"{url}/api/v1/query",
        auth_header=f"Bearer {api_key}",
        body=query_body,
        timeout=_COLLECTOR_HTTP_TIMEOUT,
    )

    if data is None:
        log.warning("Failed to query TheHive cases")
        return []

    cases = data if isinstance(data, list) else []
    log.info("Collected %d TheHive cases", len(cases))
    return cases


def collect_misp_events(
    start_iso: str,
    end_iso: str,
    url: str = "https://localhost:8443",
    api_key: str = "",
) -> list[dict]:
    """Query MISP API for events correlated during the run."""
    if not api_key:
        log.info("No MISP API key, skipping event collection")
        return []

    # Convert ISO to UNIX timestamp for MISP
    try:
        start_ts = str(int(datetime.fromisoformat(start_iso).timestamp()))
    except ValueError:
        start_ts = "0"

    query_body = {
        "returnFormat": "json",
        "timestamp": start_ts,
        "limit": 1000,
    }

    data = _curl_json(
        f"{url}/events/restSearch",
        auth_header=api_key,
        body=query_body,
        insecure=True,
        timeout=_COLLECTOR_HTTP_TIMEOUT,
    )

    if data is None:
        log.warning("Failed to query MISP events")
        return []

    events = data.get("response", []) if isinstance(data, dict) else []

    # Post-filter by end time — MISP timestamp param only supports lower bound
    end_dt = datetime.fromisoformat(end_iso)
    filtered = []
    for evt in events:
        evt_data = evt.get("Event", evt)
        ts_str = evt_data.get("timestamp", "")
        if ts_str:
            try:
                evt_dt = datetime.fromtimestamp(int(ts_str), tz=timezone.utc)
                if evt_dt <= end_dt:
                    filtered.append(evt)
            except (ValueError, OSError):
                filtered.append(evt)
        else:
            filtered.append(evt)
    events = filtered

    log.info("Collected %d MISP events", len(events))
    return events


def collect_shuffle_executions(
    start_iso: str,
    end_iso: str,
    url: str = "http://localhost:5001",
    api_key: str = "",
) -> list[dict]:
    """Query Shuffle API for workflow executions during the run."""
    if not api_key:
        log.info("No Shuffle API key, skipping execution collection")
        return []

    data = _curl_json(
        f"{url}/api/v1/workflows/executions",
        auth_header=f"Bearer {api_key}",
        timeout=_COLLECTOR_HTTP_TIMEOUT,
    )

    if data is None:
        log.warning("Failed to query Shuffle executions")
        return []

    executions = data if isinstance(data, list) else []

    # Filter by time window
    start_dt = datetime.fromisoformat(start_iso)
    end_dt = datetime.fromisoformat(end_iso)
    filtered = []
    for ex in executions:
        started = ex.get("started_at", "")
        if started:
            try:
                ex_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                if start_dt <= ex_dt <= end_dt:
                    filtered.append(ex)
            except ValueError:
                continue

    log.info("Collected %d Shuffle executions", len(filtered))
    return filtered


def collect_container_logs(
    containers: list[str],
    start_iso: str,
    end_iso: str,
    backend: "DeploymentBackend",
) -> dict[str, str]:
    """Collect docker logs per container for the time window."""
    logs: dict[str, str] = {}

    for container in containers:
        try:
            result = backend.container_logs_capture(
                container, since=start_iso, until=end_iso, timeout=30
            )
        except (BackendTimeoutError, OSError) as e:
            log.warning("Log collection failed for %s: %s", container, e)
            continue
        if result.returncode != 0:
            log.warning("Could not collect logs from container %s", container)
            continue

        # Combine stdout and stderr
        output = result.stdout
        if result.stderr:
            output += "\n--- stderr ---\n" + result.stderr

        if output.strip():
            logs[container] = output

    log.info("Collected logs from %d containers", len(logs))
    return logs


def collect_traces(
    trace_id: str,
    tempo_url: str | None = None,
) -> list[dict]:
    """Fetch all spans for a trace from Grafana Tempo.

    Queries the Tempo HTTP API by trace ID and returns the spans
    in OTLP JSON format.

    Args:
        trace_id: The hex trace ID to query.
        tempo_url: Base URL for Tempo. Defaults to ``TEMPO_URL`` env
            var or ``http://localhost:3200``.

    Returns:
        List of span dicts, or empty list on error.
    """
    if not trace_id:
        log.info("No trace_id provided, skipping trace collection")
        return []

    url = tempo_url or os.getenv("TEMPO_URL", "http://localhost:3200")
    api_url = f"{url}/api/traces/{trace_id}"

    result = _curl_json(api_url, timeout=30)
    if result is None:
        log.warning("Failed to fetch traces from Tempo at %s", api_url)
        return []

    # Tempo returns { batches: [ { resource: {...}, scopeSpans: [...] } ] }
    # or { resourceSpans: [...] } depending on version. Normalize to span list.
    spans: list[dict] = []
    if isinstance(result, dict):
        # Tempo v2 format: batches -> scopeSpans -> spans
        for batch in result.get("batches", result.get("resourceSpans", [])):
            resource = batch.get("resource", {})
            for scope_span in batch.get("scopeSpans", []):
                for span in scope_span.get("spans", []):
                    enriched = {**span, "resource": resource}
                    spans.append(enriched)

    log.info("Collected %d spans from Tempo for trace %s", len(spans), trace_id[:16])
    return spans
