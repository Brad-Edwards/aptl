"""Wazuh Alert Observer.

Queries the Wazuh Indexer (OpenSearch) API to check for alerts matching
objective criteria. Uses urllib.request with basic auth and optional TLS
verification bypass for self-signed certificates.
"""

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from aptl.core.objectives import ObjectiveResult, ObjectiveStatus
from aptl.core.scenarios import ObserverError, WazuhAlertValidation
from aptl.utils.logging import get_logger

log = get_logger("observer")


@dataclass
class WazuhConnection:
    """Connection parameters for the Wazuh Indexer API.

    Attributes:
        url: Base URL (e.g., "https://localhost:9200").
        username: Basic auth username.
        password: Basic auth password.
        verify_ssl: Whether to verify TLS certificates.
    """

    url: str
    username: str
    password: str
    verify_ssl: bool = False


def _build_ssl_context(verify: bool) -> ssl.SSLContext:
    """Create an SSL context for urllib requests.

    Args:
        verify: If False, disables hostname checking and certificate
            verification (matching the curl -k pattern).

    Returns:
        Configured SSLContext.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_auth_header(username: str, password: str) -> str:
    """Build a Basic Authorization header value.

    Args:
        username: The username.
        password: The password.

    Returns:
        The header value string (e.g., "Basic dXNlcjpwYXNz").
    """
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def query_wazuh_alerts(
    conn: WazuhConnection,
    query: dict,
    index_pattern: str = "wazuh-alerts-4.x-*",
    size: int = 100,
) -> list[dict]:
    """Execute an Elasticsearch query against the Wazuh Indexer.

    Uses urllib.request to make an HTTPS POST with basic auth.

    Args:
        conn: Wazuh connection parameters.
        query: Elasticsearch query DSL body.
        index_pattern: Index pattern to search.
        size: Maximum number of results.

    Returns:
        List of hit documents (the '_source' of each hit).

    Raises:
        ObserverError: If the query fails (network, auth, query syntax).
    """
    url = f"{conn.url.rstrip('/')}/{index_pattern}/_search"
    body = json.dumps({"query": query, "size": size}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": _build_auth_header(conn.username, conn.password),
        },
    )

    ssl_ctx = _build_ssl_context(conn.verify_ssl)

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise ObserverError(
            f"Wazuh query failed with HTTP {e.code}: {body_text}"
        ) from e
    except (urllib.error.URLError, OSError) as e:
        raise ObserverError(f"Wazuh query failed: {e}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ObserverError(f"Invalid JSON response from Wazuh: {e}") from e

    hits = data.get("hits", {}).get("hits", [])
    sources = [hit["_source"] for hit in hits if "_source" in hit]

    log.debug(
        "Wazuh query returned %d hits from %s",
        len(sources),
        index_pattern,
    )
    return sources


def check_alert_objective(
    conn: WazuhConnection,
    validation: WazuhAlertValidation,
    scenario_start_time: str,
) -> ObjectiveResult:
    """Check if a wazuh_alert objective has been satisfied.

    Builds a time-bounded query using the validation config and
    scenario start time, executes it, and checks if the minimum
    match count is met.

    Args:
        conn: Wazuh connection parameters.
        validation: The objective's WazuhAlertValidation config.
        scenario_start_time: ISO 8601 timestamp of scenario start.

    Returns:
        ObjectiveResult with COMPLETED or PENDING status.
    """
    # Build a bool query combining the user's query with a time range
    time_filter = {
        "range": {
            "timestamp": {
                "gte": scenario_start_time,
                "format": "strict_date_optional_time",
            }
        }
    }

    combined_query = {
        "bool": {
            "must": [
                validation.query,
                time_filter,
            ]
        }
    }

    try:
        hits = query_wazuh_alerts(
            conn,
            combined_query,
            size=validation.min_matches,
        )
    except ObserverError:
        log.warning("Wazuh alert check failed, treating as pending")
        return ObjectiveResult(
            objective_id="",
            status=ObjectiveStatus.PENDING,
            details="Wazuh query failed",
        )

    if len(hits) >= validation.min_matches:
        return ObjectiveResult(
            objective_id="",
            status=ObjectiveStatus.COMPLETED,
            points_awarded=0,
            details=f"Matched {len(hits)} alerts (required: {validation.min_matches})",
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

    return ObjectiveResult(
        objective_id="",
        status=ObjectiveStatus.PENDING,
        details=f"Matched {len(hits)} of {validation.min_matches} required alerts",
    )
