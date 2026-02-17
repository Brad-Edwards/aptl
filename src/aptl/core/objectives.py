"""Objective evaluation types and dispatching.

Provides data types for objective evaluation results and status tracking.
Dispatches to the appropriate checker based on ObjectiveType: manual
objectives always return PENDING, wazuh_alert objectives query the
Wazuh Indexer, and command_output/file_exists objectives use docker exec.
"""

import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from aptl.utils.logging import get_logger

log = get_logger("objectives")


class ObjectiveStatus(str, Enum):
    """Status of an objective evaluation."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ObjectiveResult:
    """Result of evaluating a single objective.

    Attributes:
        objective_id: ID of the evaluated objective.
        status: Current evaluation status.
        points_awarded: Points earned (0 if not completed).
        details: Human-readable evaluation details.
        completed_at: ISO 8601 UTC timestamp when completed.
    """

    objective_id: str
    status: ObjectiveStatus
    points_awarded: int = 0
    details: str = ""
    completed_at: Optional[str] = None


@dataclass
class EvaluationResult:
    """Aggregated result of evaluating all objectives.

    Attributes:
        results: Per-objective evaluation results.
        all_complete: True if every objective is COMPLETED.
        evaluated_at: ISO 8601 UTC timestamp of the evaluation.
    """

    results: list[ObjectiveResult]
    all_complete: bool
    evaluated_at: str


# ---------------------------------------------------------------------------
# Internal checkers
# ---------------------------------------------------------------------------


def _docker_exec(container: str, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command inside a Docker container.

    Args:
        container: Container name (e.g., "aptl-victim").
        command: Shell command to execute.
        timeout: Timeout in seconds.

    Returns:
        CompletedProcess with stdout/stderr.

    Raises:
        subprocess.TimeoutExpired: If the command times out.
        FileNotFoundError: If docker is not installed.
        OSError: On other OS-level errors.
    """
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _check_manual(objective_id: str) -> ObjectiveResult:
    """Check a manual objective (always PENDING)."""
    return ObjectiveResult(
        objective_id=objective_id,
        status=ObjectiveStatus.PENDING,
        details="Manual objective: requires explicit completion",
    )


def _check_wazuh_alert(
    objective_id: str,
    objective: "Objective",
    wazuh_conn: "Optional[WazuhConnection]",
    scenario_start_time: str,
) -> ObjectiveResult:
    """Check a wazuh_alert objective via the Wazuh Indexer.

    Imports observer module lazily to avoid circular imports.
    """
    if wazuh_conn is None:
        return ObjectiveResult(
            objective_id=objective_id,
            status=ObjectiveStatus.PENDING,
            details="No Wazuh connection available",
        )

    from aptl.core.observer import check_alert_objective

    return check_alert_objective(
        wazuh_conn,
        objective.wazuh_alert,
        scenario_start_time,
        objective_id=objective_id,
    )


def _check_command_output(
    objective_id: str,
    objective: "Objective",
) -> ObjectiveResult:
    """Check a command_output objective via docker exec."""
    validation = objective.command_output
    container = f"aptl-{validation.container}"

    try:
        result = _docker_exec(container, validation.command)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning(
            "Command check failed for objective '%s': %s",
            objective_id,
            e,
        )
        return ObjectiveResult(
            objective_id=objective_id,
            status=ObjectiveStatus.PENDING,
            details=f"Command execution failed: {e}",
        )

    stdout = result.stdout

    # Check 'contains' conditions
    for expected in validation.contains:
        if expected not in stdout:
            return ObjectiveResult(
                objective_id=objective_id,
                status=ObjectiveStatus.PENDING,
                details=f"Output missing expected string: '{expected}'",
            )

    # Check regex condition
    if validation.regex:
        if not re.search(validation.regex, stdout):
            return ObjectiveResult(
                objective_id=objective_id,
                status=ObjectiveStatus.PENDING,
                details=f"Output does not match regex: '{validation.regex}'",
            )

    return ObjectiveResult(
        objective_id=objective_id,
        status=ObjectiveStatus.COMPLETED,
        details="Command output matches all criteria",
        completed_at=datetime.now(timezone.utc).isoformat(),
    )


def _check_file_exists(
    objective_id: str,
    objective: "Objective",
) -> ObjectiveResult:
    """Check a file_exists objective via docker exec."""
    validation = objective.file_exists
    container = f"aptl-{validation.container}"

    safe_path = shlex.quote(validation.path)
    try:
        result = _docker_exec(container, f"cat {safe_path}")
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        log.warning(
            "File check failed for objective '%s': %s",
            objective_id,
            e,
        )
        return ObjectiveResult(
            objective_id=objective_id,
            status=ObjectiveStatus.PENDING,
            details=f"File check failed: {e}",
        )

    if result.returncode != 0:
        return ObjectiveResult(
            objective_id=objective_id,
            status=ObjectiveStatus.PENDING,
            details=f"File not found: {validation.path}",
        )

    # Check content if required
    if validation.contains is not None:
        if validation.contains not in result.stdout:
            return ObjectiveResult(
                objective_id=objective_id,
                status=ObjectiveStatus.PENDING,
                details=f"File missing expected content: '{validation.contains}'",
            )

    return ObjectiveResult(
        objective_id=objective_id,
        status=ObjectiveStatus.COMPLETED,
        details=f"File exists: {validation.path}",
        completed_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_objective(
    objective: "Objective",
    *,
    wazuh_conn: "Optional[WazuhConnection]" = None,
    scenario_start_time: str = "",
    project_dir: Optional[Path] = None,
) -> ObjectiveResult:
    """Evaluate a single objective.

    Dispatches to the appropriate checker based on objective type:
    - MANUAL: Always returns PENDING (requires explicit user completion)
    - WAZUH_ALERT: Queries Wazuh via observer
    - COMMAND_OUTPUT: Executes command in container via docker exec
    - FILE_EXISTS: Checks file existence in container via docker exec

    Args:
        objective: The objective to evaluate.
        wazuh_conn: Wazuh connection (required for wazuh_alert type).
        scenario_start_time: When the scenario started (for time-bounded queries).
        project_dir: Project directory (for docker exec commands).

    Returns:
        ObjectiveResult with current status.

    Raises:
        ValueError: If required parameters are missing for the objective type.
    """
    from aptl.core.scenarios import ObjectiveType

    obj_id = objective.id

    if objective.type == ObjectiveType.MANUAL:
        return _check_manual(obj_id)

    if objective.type == ObjectiveType.WAZUH_ALERT:
        if objective.wazuh_alert is None:
            raise ValueError(
                f"Objective '{obj_id}' is wazuh_alert type but missing "
                "wazuh_alert validation config"
            )
        return _check_wazuh_alert(obj_id, objective, wazuh_conn, scenario_start_time)

    if objective.type == ObjectiveType.COMMAND_OUTPUT:
        if objective.command_output is None:
            raise ValueError(
                f"Objective '{obj_id}' is command_output type but missing "
                "command_output validation config"
            )
        return _check_command_output(obj_id, objective)

    if objective.type == ObjectiveType.FILE_EXISTS:
        if objective.file_exists is None:
            raise ValueError(
                f"Objective '{obj_id}' is file_exists type but missing "
                "file_exists validation config"
            )
        return _check_file_exists(obj_id, objective)

    return ObjectiveResult(
        objective_id=obj_id,
        status=ObjectiveStatus.PENDING,
        details=f"Unknown objective type: {objective.type}",
    )


def evaluate_all(
    objectives: "list[Objective]",
    *,
    wazuh_conn: "Optional[WazuhConnection]" = None,
    scenario_start_time: str = "",
    project_dir: Optional[Path] = None,
    completed_ids: Optional[set[str]] = None,
) -> EvaluationResult:
    """Evaluate all objectives, skipping already-completed ones.

    Args:
        objectives: All objectives to evaluate.
        wazuh_conn: Wazuh connection parameters.
        scenario_start_time: Scenario start timestamp.
        project_dir: Project directory.
        completed_ids: Set of objective IDs already completed (skip these).

    Returns:
        EvaluationResult with per-objective results.
    """
    if completed_ids is None:
        completed_ids = set()

    results: list[ObjectiveResult] = []
    for obj in objectives:
        if obj.id in completed_ids:
            results.append(ObjectiveResult(
                objective_id=obj.id,
                status=ObjectiveStatus.COMPLETED,
                points_awarded=obj.points,
                details="Previously completed",
            ))
            continue

        result = evaluate_objective(
            obj,
            wazuh_conn=wazuh_conn,
            scenario_start_time=scenario_start_time,
            project_dir=project_dir,
        )
        results.append(result)

    all_complete = all(r.status == ObjectiveStatus.COMPLETED for r in results)

    log.info(
        "Evaluated %d objectives: %d completed, %d pending",
        len(results),
        sum(1 for r in results if r.status == ObjectiveStatus.COMPLETED),
        sum(1 for r in results if r.status == ObjectiveStatus.PENDING),
    )

    return EvaluationResult(
        results=results,
        all_complete=all_complete,
        evaluated_at=datetime.now(timezone.utc).isoformat(),
    )
