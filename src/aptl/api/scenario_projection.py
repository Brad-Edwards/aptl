"""ACES scenario-detail workbench projection (UI-008d).

Turns a curated catalog entry plus its parsed ACES ``Scenario`` into the
backend-owned wire DTOs in :mod:`aptl.api.schemas`: the enriched card summary
and the scenario-detail response (header facts + an ordered ``WorkbenchBlock``
discriminated union).

The block families are projected from whatever the ACES SDL actually owns and
are omitted when their source section is empty — the projection never
fabricates steps, objectives, or SIEM queries for infra-only scenarios. The
catalog ``path`` locator is never read into any wire field.
"""

from __future__ import annotations

from typing import Optional, TypedDict

from aptl.api.schemas import (
    ContainerStatusBlock,
    NarrativeBlock,
    ObjectiveBlock,
    ScenarioDetailResponse,
    ScenarioDifficultyLiteral,
    ScenarioModeLiteral,
    ScenarioSummaryResponse,
    ScenarioValidationState,
    SectionDividerBlock,
    StepBlock,
    TerminalBlock,
    WorkbenchBlock,
)
from aptl.core.scenario_catalog import ScenarioCatalogEntry


class MetadataFacts(TypedDict):
    """The card facts drawn from the narrow catalog metadata extension."""

    mode: Optional[ScenarioModeLiteral]
    difficulty: Optional[ScenarioDifficultyLiteral]
    estimated_minutes: Optional[int]
    tags: list[str]


def _node_type(node: object) -> str:
    """Return the node's ACES type string (``vm`` / ``switch``), or ``""``."""
    node_type = getattr(node, "type", None)
    return getattr(node_type, "value", node_type) or ""


def _is_vm(node: object) -> bool:
    """Return whether an ACES node is a VM (a candidate required container)."""
    return _node_type(node) == "vm"


def _exposes_ssh(node: object) -> bool:
    """Return whether a node exposes an SSH service (by service name or port 22)."""
    for service in getattr(node, "services", []) or []:
        if (
            getattr(service, "name", "") == "ssh"
            or getattr(service, "port", None) == 22
        ):
            return True
    return False


def scenario_required_containers(scenario: object) -> list[str]:
    """Return the required-container names: the scenario's ACES VM nodes."""
    nodes = getattr(scenario, "nodes", {}) or {}
    return [name for name, node in nodes.items() if _is_vm(node)]


def _ssh_containers(scenario: object) -> list[str]:
    """Return the VM node names that expose an SSH service."""
    nodes = getattr(scenario, "nodes", {}) or {}
    return [name for name, node in nodes.items() if _is_vm(node) and _exposes_ssh(node)]


def _metadata_facts(entry: ScenarioCatalogEntry) -> MetadataFacts:
    """Extract the catalog metadata card facts, defaulting each to absent."""
    meta = getattr(entry, "metadata", None)
    if meta is None:
        return {"mode": None, "difficulty": None, "estimated_minutes": None, "tags": []}
    return {
        "mode": meta.mode,
        "difficulty": meta.difficulty,
        "estimated_minutes": meta.estimated_minutes,
        "tags": list(meta.tags),
    }


def _title_narrative(
    entry: ScenarioCatalogEntry, facts: MetadataFacts
) -> NarrativeBlock:
    """Build the title narrative block (name, description, metadata line)."""
    parts: list[str] = []
    if facts["mode"]:
        parts.append(f"**Mode:** {facts['mode']}")
    if facts["difficulty"]:
        parts.append(f"**Difficulty:** {facts['difficulty']}")
    if facts["estimated_minutes"]:
        parts.append(f"**Time:** ~{facts['estimated_minutes']} min")
    if facts["tags"]:
        parts.append(f"**Tags:** {', '.join(facts['tags'])}")
    meta_line = f"\n\n{' | '.join(parts)}" if parts else ""
    content = f"# {entry.name}\n\n{entry.description}{meta_line}"
    return NarrativeBlock(key="narrative-title", content=content)


def _objective_success_summary(success: object) -> str:
    """Render an ACES objective's declarative success criteria as display copy."""
    mode = getattr(success, "mode", "")
    mode_label = getattr(mode, "value", mode) or "all_of"
    groups = [
        ("conditions", getattr(success, "conditions", []) or []),
        ("metrics", getattr(success, "metrics", []) or []),
        ("evaluations", getattr(success, "evaluations", []) or []),
        ("tlos", getattr(success, "tlos", []) or []),
        ("goals", getattr(success, "goals", []) or []),
    ]
    parts = [f"{label} {', '.join(refs)}" for label, refs in groups if refs]
    return f"{mode_label}: {'; '.join(parts)}" if parts else str(mode_label)


def _objective_blocks(scenario: object) -> list[WorkbenchBlock]:
    """Project ACES declarative objectives into objective blocks (empty if none)."""
    objectives = getattr(scenario, "objectives", {}) or {}
    if not objectives:
        return []
    blocks: list[WorkbenchBlock] = [
        SectionDividerBlock(key="divider-objectives", title="Objectives")
    ]
    for obj_id, objective in objectives.items():
        blocks.append(
            ObjectiveBlock(
                key=f"objective-{obj_id}",
                name=getattr(objective, "name", "") or obj_id,
                description=getattr(objective, "description", "") or "",
                success=_objective_success_summary(getattr(objective, "success", None)),
            )
        )
    return blocks


def _step_blocks(scenario: object) -> list[WorkbenchBlock]:
    """Project ACES workflow steps into ordered step blocks (empty if none)."""
    workflows = getattr(scenario, "workflows", {}) or {}
    if not workflows:
        return []
    blocks: list[WorkbenchBlock] = [
        SectionDividerBlock(key="divider-steps", title="Steps")
    ]
    index = 0
    for wf_id, workflow in workflows.items():
        steps = getattr(workflow, "steps", {}) or {}
        for step_id, step in steps.items():
            step_type = getattr(step, "type", "")
            blocks.append(
                StepBlock(
                    key=f"step-{wf_id}-{step_id}",
                    index=index,
                    name=step_id,
                    description=(
                        getattr(step, "description", "")
                        or getattr(step, "objective", "")
                        or ""
                    ),
                    step_type=getattr(step_type, "value", step_type) or "",
                )
            )
            index += 1
    return blocks


def _terminal_blocks(scenario: object) -> list[WorkbenchBlock]:
    """Project SSH-exposing VM nodes into lazy terminal blocks (empty if none)."""
    ssh_containers = _ssh_containers(scenario)
    if not ssh_containers:
        return []
    blocks: list[WorkbenchBlock] = [
        SectionDividerBlock(key="divider-terminals", title="Terminals")
    ]
    for container in ssh_containers:
        blocks.append(
            TerminalBlock(
                key=f"terminal-{container}", container=container, label=container
            )
        )
    return blocks


def build_workbench_blocks(
    entry: ScenarioCatalogEntry, scenario: object, facts: MetadataFacts
) -> list[WorkbenchBlock]:
    """Project the ordered ``WorkbenchBlock`` union from ACES scenario data."""
    blocks: list[WorkbenchBlock] = [_title_narrative(entry, facts)]
    containers = scenario_required_containers(scenario)
    if containers:
        blocks.append(
            ContainerStatusBlock(key="container-status", containers=containers)
        )
    blocks.extend(_objective_blocks(scenario))
    blocks.extend(_step_blocks(scenario))
    blocks.extend(_terminal_blocks(scenario))
    return blocks


def build_scenario_detail(
    entry: ScenarioCatalogEntry, scenario: object
) -> ScenarioDetailResponse:
    """Build the scenario-detail response from a catalog entry + parsed SDL."""
    facts = _metadata_facts(entry)
    return ScenarioDetailResponse(
        id=entry.id,
        name=entry.name,
        description=entry.description,
        mode=facts["mode"],
        difficulty=facts["difficulty"],
        estimated_minutes=facts["estimated_minutes"],
        tags=facts["tags"],
        required_containers=scenario_required_containers(scenario),
        validation=ScenarioValidationState(valid=True),
        blocks=build_workbench_blocks(entry, scenario, facts),
    )


def build_scenario_summary(
    entry: ScenarioCatalogEntry, scenario: object
) -> ScenarioSummaryResponse:
    """Build an enriched card summary from a catalog entry + parsed SDL."""
    facts = _metadata_facts(entry)
    return ScenarioSummaryResponse(
        id=entry.id,
        name=entry.name,
        description=entry.description,
        mode=facts["mode"],
        difficulty=facts["difficulty"],
        estimated_minutes=facts["estimated_minutes"],
        tags=facts["tags"],
        required_containers=scenario_required_containers(scenario),
        validation=ScenarioValidationState(valid=True),
    )


def invalid_scenario_summary(entry: ScenarioCatalogEntry) -> ScenarioSummaryResponse:
    """Build a card summary for an entry whose ACES SDL failed to project.

    Carries the catalog-owned facts (id/name/description/metadata) and a
    redacted, path-free invalid validation state so the card renders without
    the workbench being reachable.
    """
    facts = _metadata_facts(entry)
    return ScenarioSummaryResponse(
        id=entry.id,
        name=entry.name,
        description=entry.description,
        mode=facts["mode"],
        difficulty=facts["difficulty"],
        estimated_minutes=facts["estimated_minutes"],
        tags=facts["tags"],
        required_containers=[],
        validation=ScenarioValidationState(
            valid=False, detail="Scenario projection is currently unavailable."
        ),
    )
