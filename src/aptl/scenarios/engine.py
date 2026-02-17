"""Scenario execution and scoring engine.

Loads scenario definitions, tracks execution, queries SIEM for
detections, and computes coverage scores.
"""

import json
from pathlib import Path

from aptl.scenarios.models import (
    DetectionResult,
    Scenario,
    ScenarioScore,
)
from aptl.utils.logging import get_logger

log = get_logger("scenarios")


def load_scenario(path: Path) -> Scenario:
    """Load a scenario definition from a JSON file.

    Args:
        path: Path to the scenario JSON file.

    Returns:
        Validated Scenario instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON is invalid or fails validation.
    """
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")

    raw = path.read_text().strip()
    if not raw:
        raise ValueError(f"Scenario file is empty: {path}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e

    return Scenario(**data)


def list_scenarios(scenarios_dir: Path) -> list[Scenario]:
    """List all available scenarios from a directory.

    Args:
        scenarios_dir: Directory containing scenario JSON files.

    Returns:
        List of validated Scenario instances.
    """
    scenarios = []
    if not scenarios_dir.exists():
        log.warning("Scenarios directory not found: %s", scenarios_dir)
        return scenarios

    for path in sorted(scenarios_dir.glob("*.json")):
        try:
            scenario = load_scenario(path)
            scenarios.append(scenario)
        except (ValueError, FileNotFoundError) as e:
            log.warning("Skipping invalid scenario %s: %s", path.name, e)

    return scenarios


def score_scenario(
    scenario: Scenario,
    results: list[DetectionResult],
) -> ScenarioScore:
    """Compute a detection coverage score for a scenario run.

    Args:
        scenario: The scenario definition.
        results: Detection results for each step.

    Returns:
        ScenarioScore with coverage metrics.
    """
    total = len(scenario.steps)
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
    for step in scenario.steps:
        tid = step.technique.technique_id
        step_result = next(
            (r for r in results if r.technique_id == tid),
            None,
        )
        mitre_coverage[tid] = (
            step_result.detected if step_result else False
        )

    gaps = [
        tid for tid, det in mitre_coverage.items() if not det
    ]

    return ScenarioScore(
        scenario_id=scenario.id,
        total_steps=total,
        detected_steps=detected,
        detection_coverage=coverage,
        avg_detection_time_seconds=avg_time,
        results=results,
        mitre_coverage=mitre_coverage,
        gaps=gaps,
    )


def format_score_report(scenario: Scenario, score: ScenarioScore) -> str:
    """Format a human-readable score report.

    Args:
        scenario: The scenario definition.
        score: The scoring results.

    Returns:
        Formatted report string.
    """
    cov = score.detection_coverage
    lines = [
        f"=== Scenario: {scenario.name} ===",
        f"Difficulty: {scenario.difficulty.value}",
        f"Attack Chain: {scenario.attack_chain}",
        "",
        f"Detection Coverage: "
        f"{score.detected_steps}/{score.total_steps} "
        f"({cov:.0%})",
    ]

    avg = score.avg_detection_time_seconds
    if avg is not None:
        lines.append(f"Avg Detection Time: {avg:.1f}s")

    lines.append("")
    lines.append("Step Results:")

    for result in score.results:
        step = next(
            (s for s in scenario.steps
             if s.technique.technique_id == result.technique_id),
            None,
        )
        if step:
            status = "DETECTED" if result.detected else "MISSED"
            dt = result.detection_time_seconds
            time_str = f" ({dt:.1f}s)" if dt else ""
            tid = step.technique.technique_id
            tname = step.technique.technique_name
            lines.append(
                f"  [{status}] Step {result.step_number}: "
                f"{tid} {tname}{time_str}"
            )

    if score.gaps:
        lines.append("")
        lines.append("Detection Gaps:")
        for tid in score.gaps:
            step = next(
                (s for s in scenario.steps
                 if s.technique.technique_id == tid),
                None,
            )
            if step:
                tname = step.technique.technique_name
                tactic = step.technique.tactic
                lines.append(
                    f"  - {tid}: {tname} ({tactic})"
                )

    lines.append("")
    lines.append("MITRE ATT&CK Coverage:")
    for tid, det in score.mitre_coverage.items():
        label = "covered" if det else "GAP"
        lines.append(f"  {tid}: {label}")

    return "\n".join(lines)
