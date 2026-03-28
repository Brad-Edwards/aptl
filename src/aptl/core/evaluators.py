"""Objective evaluation executors for live infrastructure checks.

Each evaluator checks one objective validation type against running
containers and services. All evaluators are async (wrapping blocking
I/O via ``asyncio.to_thread``) and fault-tolerant: they return
``EvaluationResult(passed=False)`` on error and never raise.
"""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from aptl.core.collectors import _curl_json, _run_cmd
from aptl.core.scenarios import (
    CommandOutputValidation,
    FileExistsValidation,
    Objective,
    ObjectiveType,
    WazuhAlertValidation,
)
from aptl.utils.logging import get_logger

log = get_logger("evaluators")


@dataclass
class EvaluationResult:
    """Result of evaluating a single objective."""

    objective_id: str
    passed: bool
    detail: str
    checked_at: str


async def evaluate_wazuh_alert(
    objective_id: str,
    validation: WazuhAlertValidation,
    session_started_at: str,
    indexer_url: str = "https://localhost:9200",
    auth: tuple[str, str] = ("admin", "SecretPassword"),
) -> EvaluationResult:
    """Query Wazuh Indexer for alerts matching the objective's ES query.

    Wraps the objective's query in a time-range filter scoped to
    the sliding window (now - time_window_seconds, now). Checks
    whether at least ``min_matches`` hits are returned.
    """
    now = datetime.now(timezone.utc)
    checked_at = now.isoformat()

    # Use the later of: (now - time_window_seconds) or session start
    window_start_dt = now - timedelta(seconds=validation.time_window_seconds)
    session_start_dt = datetime.fromisoformat(session_started_at)
    if not session_start_dt.tzinfo:
        session_start_dt = session_start_dt.replace(tzinfo=timezone.utc)
    if window_start_dt < session_start_dt:
        window_start_dt = session_start_dt

    query = {
        "query": {
            "bool": {
                "must": [
                    validation.query,
                    {
                        "range": {
                            "@timestamp": {
                                "gte": window_start_dt.isoformat(),
                                "lte": checked_at,
                            }
                        }
                    },
                ],
            }
        },
        "size": 0,
        "track_total_hits": True,
    }

    url = f"{indexer_url}/wazuh-alerts-4.x-*/_search"

    try:
        data = await asyncio.to_thread(
            _curl_json, url, auth=auth, body=query, insecure=True, timeout=30
        )
    except Exception as e:
        log.warning("Wazuh alert evaluation failed for %s: %s", objective_id, e)
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail=f"Query error: {e}",
            checked_at=checked_at,
        )

    if data is None:
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail="Wazuh Indexer unreachable or query failed",
            checked_at=checked_at,
        )

    total_hits = 0
    if isinstance(data, dict):
        hits = data.get("hits", {})
        total = hits.get("total", {})
        if isinstance(total, dict):
            total_hits = total.get("value", 0)
        elif isinstance(total, int):
            total_hits = total

    passed = total_hits >= validation.min_matches
    detail = (
        f"{total_hits} matches (need {validation.min_matches})"
        if not passed
        else f"{total_hits} matches found"
    )

    log.info(
        "Wazuh alert eval for %s: %d hits, need %d -> %s",
        objective_id,
        total_hits,
        validation.min_matches,
        "PASS" if passed else "FAIL",
    )

    return EvaluationResult(
        objective_id=objective_id,
        passed=passed,
        detail=detail,
        checked_at=checked_at,
    )


async def evaluate_command_output(
    objective_id: str,
    validation: CommandOutputValidation,
) -> EvaluationResult:
    """Run a command in a container and check its output.

    Executes ``docker exec <container> sh -c '<command>'`` and checks
    stdout for required strings and optional regex match.
    """
    checked_at = datetime.now(timezone.utc).isoformat()

    cmd = [
        "docker", "exec", f"aptl-{validation.container}",
        "sh", "-c", validation.command,
    ]

    try:
        result = await asyncio.to_thread(_run_cmd, cmd, 30)
    except Exception as e:
        log.warning("Command output evaluation failed for %s: %s", objective_id, e)
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail=f"Execution error: {e}",
            checked_at=checked_at,
        )

    if result is None or result.returncode != 0:
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail="Command failed or container unreachable",
            checked_at=checked_at,
        )

    output = result.stdout

    # Check all required strings
    for required in validation.contains:
        if required not in output:
            return EvaluationResult(
                objective_id=objective_id,
                passed=False,
                detail=f"Missing required string: {required!r}",
                checked_at=checked_at,
            )

    # Check optional regex
    if validation.regex is not None and not re.search(validation.regex, output):
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail=f"Regex not matched: {validation.regex}",
            checked_at=checked_at,
        )

    log.info("Command output eval for %s: PASS", objective_id)
    return EvaluationResult(
        objective_id=objective_id,
        passed=True,
        detail="All checks passed",
        checked_at=checked_at,
    )


async def evaluate_file_exists(
    objective_id: str,
    validation: FileExistsValidation,
) -> EvaluationResult:
    """Check whether a file exists in a container, optionally checking content.

    Uses ``docker exec <container> cat <path>`` to both verify existence
    and read content in one call.
    """
    checked_at = datetime.now(timezone.utc).isoformat()

    cmd = [
        "docker", "exec", f"aptl-{validation.container}",
        "cat", validation.path,
    ]

    try:
        result = await asyncio.to_thread(_run_cmd, cmd, 30)
    except Exception as e:
        log.warning("File exists evaluation failed for %s: %s", objective_id, e)
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail=f"Execution error: {e}",
            checked_at=checked_at,
        )

    if result is None or result.returncode != 0:
        return EvaluationResult(
            objective_id=objective_id,
            passed=False,
            detail=f"File not found: {validation.path}",
            checked_at=checked_at,
        )

    # Optionally check content
    if validation.contains is not None:
        if validation.contains not in result.stdout:
            return EvaluationResult(
                objective_id=objective_id,
                passed=False,
                detail=f"File exists but missing content: {validation.contains!r}",
                checked_at=checked_at,
            )

    log.info("File exists eval for %s: PASS", objective_id)
    return EvaluationResult(
        objective_id=objective_id,
        passed=True,
        detail=f"File exists: {validation.path}",
        checked_at=checked_at,
    )


async def evaluate_objective(
    objective: Objective,
    session_started_at: str,
) -> EvaluationResult:
    """Dispatch evaluation to the correct evaluator based on objective type.

    Returns a not-evaluable result for MANUAL objectives.
    """
    if objective.type == ObjectiveType.MANUAL:
        return EvaluationResult(
            objective_id=objective.id,
            passed=False,
            detail="Manual objective (not auto-evaluable)",
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    if objective.type == ObjectiveType.WAZUH_ALERT:
        if objective.wazuh_alert is None:
            return EvaluationResult(
                objective_id=objective.id,
                passed=False,
                detail="Missing wazuh_alert validation config",
                checked_at=datetime.now(timezone.utc).isoformat(),
            )
        return await evaluate_wazuh_alert(
            objective.id,
            objective.wazuh_alert,
            session_started_at,
        )

    if objective.type == ObjectiveType.COMMAND_OUTPUT:
        if objective.command_output is None:
            return EvaluationResult(
                objective_id=objective.id,
                passed=False,
                detail="Missing command_output validation config",
                checked_at=datetime.now(timezone.utc).isoformat(),
            )
        return await evaluate_command_output(objective.id, objective.command_output)

    if objective.type == ObjectiveType.FILE_EXISTS:
        if objective.file_exists is None:
            return EvaluationResult(
                objective_id=objective.id,
                passed=False,
                detail="Missing file_exists validation config",
                checked_at=datetime.now(timezone.utc).isoformat(),
            )
        return await evaluate_file_exists(objective.id, objective.file_exists)

    return EvaluationResult(
        objective_id=objective.id,
        passed=False,
        detail=f"Unknown objective type: {objective.type}",
        checked_at=datetime.now(timezone.utc).isoformat(),
    )
