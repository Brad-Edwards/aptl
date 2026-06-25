"""ACES-aligned run reproducibility record builder (REP-001 / ADR-044).

Pure composition module: anchors run identity to ACES contracts where they
exist; carries APTL-only data only as backend-owned realization evidence.
No Docker/curl/ssh calls. All inputs are already-captured objects/dicts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aces_backend_protocols.manifest import backend_manifest_payload
from aces_runtime.control_plane_store import _snapshot_payload

from aptl.backends.aces_manifest import create_aptl_manifest

if TYPE_CHECKING:
    from aces_contracts.runtime_state import RuntimeSnapshot

SCHEMA_VERSION = "aptl.run-record/v1"

_SEEDS_ABSENT_NOTE = (
    "ACES ExecutionPlan does not currently expose a scenario-level "
    "seed or parameter surface; seeds absent is the honest state."
)


@dataclass(frozen=True)
class RunRecordInputs:
    """Builder-input holder for build_reproducibility_record (REP-001 / ADR-044).

    Carries already-prepared primitives and ACES objects through to the record
    builder.  This is NOT a local mirror of any ACES task/run/apparatus/
    evidence/provenance/manifest/snapshot contract — it is a value-transport
    struct whose fields are resolved by the caller before construction.
    """

    run_id: str
    backend_name: str
    started_at: str
    finished_at: str
    outcome: str
    final_snapshot: RuntimeSnapshot
    realization_details: dict[str, Any]
    selected_profiles: list[str]
    scenario_path: Path | None
    scenario_display_name: str
    range_snapshot_dict: dict[str, Any]
    config_digests: dict[str, str]
    container_image_digests: dict[str, str]
    detection_content_digest: str
    tool_versions: dict[str, str]
    evidence_references: list[dict[str, str]]


def build_reproducibility_record(inputs: RunRecordInputs) -> dict[str, Any]:
    """Build a REP-001 run reproducibility record dict.

    Anchors ACES-contract identity at record["aces"] and carries
    APTL backend realization evidence at record["backend_evidence"].
    """
    manifest = create_aptl_manifest()
    manifest_payload = backend_manifest_payload(manifest)
    runtime_snapshot_payload = _snapshot_payload(inputs.final_snapshot)
    aces_lock_digest = _aces_lock_digest(inputs.scenario_path)

    scenario_section: dict[str, Any] = {
        "sdl_path": str(inputs.scenario_path) if inputs.scenario_path else None,
        "display_name": inputs.scenario_display_name,
        "aces_lock_digest": aces_lock_digest,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": inputs.run_id,
        "backend_name": inputs.backend_name,
        "backend_manifest_version": manifest_payload.get("schema_version", ""),
        "started_at": inputs.started_at,
        "finished_at": inputs.finished_at,
        "outcome": inputs.outcome,
        "aces": {
            "backend_manifest": manifest_payload,
            "runtime_snapshot": runtime_snapshot_payload,
            "scenario": scenario_section,
            "scenario_parameters": None,
            "scenario_parameters_note": _SEEDS_ABSENT_NOTE,
            "realization": inputs.realization_details,
        },
        "backend_evidence": {
            "selected_profiles": inputs.selected_profiles,
            "range_snapshot": inputs.range_snapshot_dict,
            "config_digests": inputs.config_digests,
            "container_image_digests": inputs.container_image_digests,
            "detection_content_digest": inputs.detection_content_digest,
            "tool_versions": inputs.tool_versions,
            "evidence_references": inputs.evidence_references,
        },
    }


def _aces_lock_digest(scenario_path: Path | None) -> str | None:
    """Compute the sha256 of aces.lock.json adjacent to scenario_path, or None."""
    if scenario_path is None:
        return None
    lock_path = scenario_path.parent / "aces.lock.json"
    if not lock_path.exists():
        return None
    return hashlib.sha256(lock_path.read_bytes()).hexdigest()
