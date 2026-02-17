"""Objective evaluation types and dispatching.

Provides data types for objective evaluation results and status tracking.
Evaluation functions that dispatch to checkers based on ObjectiveType will
be added in a later phase.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


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
