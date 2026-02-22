"""OCSF-aligned detection models and scoring.

Provides detection expectation, result, and coverage models using OCSF
(Open Cybersecurity Schema Framework) vocabulary. Includes functions for
scoring detection coverage and formatting reports.
"""

from enum import IntEnum
from typing import Optional

from pydantic import BaseModel, Field


class SeverityId(IntEnum):
    """OCSF severity_id values (0-6 scale)."""

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class ExpectedDetection(BaseModel):
    """An expected detection for an attack step, using OCSF field names."""

    product_name: str = Field(
        description="Detection source, normalized lowercase (e.g. 'wazuh', 'suricata')",
    )
    analytic_uid: Optional[str] = Field(
        default=None,
        description="Rule ID for exact match",
    )
    analytic_name: Optional[str] = Field(
        default=None,
        description="Rule name/group for substring match",
    )
    severity_id: SeverityId = Field(
        description="OCSF severity (0-6)",
    )
    description: str = Field(
        description="What the detection should identify",
    )
    max_detection_time_seconds: int = Field(
        default=60,
        description="Max seconds for detection after execution",
    )


class DetectionResult(BaseModel):
    """Result of checking whether a detection fired for a step."""

    step_number: int
    technique_id: str
    detected: bool
    severity_id: Optional[SeverityId] = None
    analytic_uid: Optional[str] = None
    analytic_name: Optional[str] = None
    product_name: Optional[str] = None
    detection_time_seconds: Optional[float] = None
    alert_id: Optional[str] = None


class DetectionCoverage(BaseModel):
    """Detection coverage scoring for a scenario run."""

    scenario_id: str
    total_steps: int
    detected_steps: int
    detection_coverage: float = Field(
        description="Fraction of steps detected (0.0-1.0)",
    )
    avg_detection_time_seconds: Optional[float] = None
    results: list[DetectionResult]
    mitre_coverage: dict[str, bool] = Field(default_factory=dict)
    gaps: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def match_detection(expected: ExpectedDetection, alert: dict) -> bool:
    """Check whether an alert dict matches an expected detection.

    Matching rules:
    - product_name: case-insensitive equality
    - analytic_uid: exact match (if specified in expected)
    - analytic_name: case-insensitive substring (if specified in expected)
    - severity_id: alert severity >= expected severity

    Args:
        expected: The detection expectation.
        alert: A dict with keys like 'product_name', 'analytic_uid',
               'analytic_name', 'severity_id'.

    Returns:
        True if the alert matches all specified criteria.
    """
    alert_product = str(alert.get("product_name", "")).lower()
    if alert_product != expected.product_name.lower():
        return False

    if expected.analytic_uid is not None:
        if str(alert.get("analytic_uid", "")) != expected.analytic_uid:
            return False

    if expected.analytic_name is not None:
        alert_name = str(alert.get("analytic_name", "")).lower()
        if expected.analytic_name.lower() not in alert_name:
            return False

    alert_severity = alert.get("severity_id")
    if alert_severity is not None:
        if int(alert_severity) < int(expected.severity_id):
            return False

    return True


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score_detection_coverage(
    scenario_id: str,
    steps: list,
    results: list[DetectionResult],
) -> DetectionCoverage:
    """Compute detection coverage score for a scenario run.

    Args:
        scenario_id: The scenario identifier.
        steps: List of AttackStep objects (must have technique_id attribute).
        results: Detection results for each step.

    Returns:
        DetectionCoverage with coverage metrics.
    """
    total = len(steps)
    detected = sum(1 for r in results if r.detected)
    coverage = detected / total if total > 0 else 0.0

    detection_times = [
        r.detection_time_seconds
        for r in results
        if r.detected and r.detection_time_seconds is not None
    ]
    avg_time = (
        sum(detection_times) / len(detection_times)
        if detection_times
        else None
    )

    mitre_coverage: dict[str, bool] = {}
    for step in steps:
        tid = step.technique_id
        step_result = next(
            (r for r in results if r.technique_id == tid),
            None,
        )
        mitre_coverage[tid] = step_result.detected if step_result else False

    gaps = [tid for tid, det in mitre_coverage.items() if not det]

    return DetectionCoverage(
        scenario_id=scenario_id,
        total_steps=total,
        detected_steps=detected,
        detection_coverage=coverage,
        avg_detection_time_seconds=avg_time,
        results=results,
        mitre_coverage=mitre_coverage,
        gaps=gaps,
    )


def format_detection_report(
    scenario_name: str,
    difficulty: str,
    attack_chain: str,
    steps: list,
    coverage: DetectionCoverage,
) -> str:
    """Format a human-readable detection coverage report.

    Args:
        scenario_name: Scenario display name.
        difficulty: Difficulty level string.
        attack_chain: Kill chain summary.
        steps: List of AttackStep objects.
        coverage: Detection coverage results.

    Returns:
        Formatted report string.
    """
    lines = [
        f"=== Scenario: {scenario_name} ===",
        f"Difficulty: {difficulty}",
        f"Attack Chain: {attack_chain}",
        "",
        f"Detection Coverage: "
        f"{coverage.detected_steps}/{coverage.total_steps} "
        f"({coverage.detection_coverage:.0%})",
    ]

    if coverage.avg_detection_time_seconds is not None:
        lines.append(f"Avg Detection Time: {coverage.avg_detection_time_seconds:.1f}s")

    lines.append("")
    lines.append("Step Results:")

    for result in coverage.results:
        step = next(
            (s for s in steps if s.technique_id == result.technique_id),
            None,
        )
        if step:
            status = "DETECTED" if result.detected else "MISSED"
            dt = result.detection_time_seconds
            time_str = f" ({dt:.1f}s)" if dt else ""
            lines.append(
                f"  [{status}] Step {result.step_number}: "
                f"{step.technique_id} {step.technique_name}{time_str}"
            )

    if coverage.gaps:
        lines.append("")
        lines.append("Detection Gaps:")
        for tid in coverage.gaps:
            step = next(
                (s for s in steps if s.technique_id == tid),
                None,
            )
            if step:
                lines.append(f"  - {tid}: {step.technique_name} ({step.tactic})")

    lines.append("")
    lines.append("MITRE ATT&CK Coverage:")
    for tid, det in coverage.mitre_coverage.items():
        label = "covered" if det else "GAP"
        lines.append(f"  {tid}: {label}")

    return "\n".join(lines)
