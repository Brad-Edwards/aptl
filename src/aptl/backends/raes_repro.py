"""RAES-aligned run reproducibility record builder (REP-001 / ADR-044).

Pure composition module: anchors run identity to RAES contracts where they
exist; carries APTL-only data only as backend-owned realization evidence.
No Docker/curl/ssh calls. All inputs are already-captured objects/dicts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raes.module_registry import LOCKFILE_NAME
from raes_backend_protocols.manifest import backend_manifest_payload
from raes_contracts.account_credentials import (
    account_placement_has_credential_bindings,
    value_free_account_placement_payload,
)
from raes_contracts.participant_autonomous_state import (
    require_participant_autonomous_runtime_snapshot,
)
from raes_contracts.realization_preparation import (
    jsonable_fallback,
    to_jsonable_python,
)
from raes_contracts.runtime_state import RuntimeSnapshotEnvelope

from aptl.backends.raes_manifest import create_aptl_manifest

if TYPE_CHECKING:
    from raes_contracts.runtime_state import RuntimeSnapshot

#: Current run-record schema. v2 renamed the contract-identity section from
#: ``raes`` to ``raes`` (and ``raes_lock_digest`` to ``raes_lock_digest``) when
#: the upstream distribution was renamed. Writers only ever emit v2; v1 records
#: already on disk stay readable through
#: :func:`aptl.core.correlation._extract.contract_section`.
SCHEMA_VERSION = "aptl.run-record/v2"

#: The v1 name of the contract-identity section, retained for reading historical
#: archives only. Never written.
LEGACY_CONTRACT_SECTION = "aces"

#: The v2 name of the contract-identity section.
CONTRACT_SECTION = "raes"

_PARAMETERS_OMITTED_NOTE = (
    "Runtime parameters are intentionally omitted; APTL does not persist raw "
    "scenario bindings or value-bearing provenance."
)


@dataclass(frozen=True)
class RunRecordInputs:
    """Builder-input holder for build_reproducibility_record (REP-001 / ADR-044).

    Carries already-prepared primitives and RAES objects through to the record
    builder.  This is NOT a local mirror of any RAES task/run/apparatus/
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
    pack_interaction_evidence: dict[str, Any]
    scenario_path: Path | None
    scenario_display_name: str
    range_snapshot_dict: dict[str, Any]
    config_digests: dict[str, str]
    container_image_digests: dict[str, str]
    detection_content_digest: str
    tool_versions: dict[str, str]
    evidence_references: list[dict[str, str]]


def runtime_snapshot_record_payload(snapshot: RuntimeSnapshot) -> dict[str, Any]:
    """Project the public RAES snapshot into the value-free REP-001 record.

    The snapshot's dataclass contract supplies the field set. Credential
    bindings in account placement are reduced through RAES's public value-free
    projection before the record reaches the run store.
    """

    require_participant_autonomous_runtime_snapshot(snapshot)
    payload = to_jsonable_python(snapshot, fallback=jsonable_fallback)
    if not isinstance(payload, dict):
        raise ValueError("RAES runtime snapshot did not encode as a mapping")
    entries = payload.get("entries")
    if not isinstance(entries, dict):
        raise ValueError("RAES runtime snapshot entries are invalid")
    for entry in entries.values():
        if not isinstance(entry, dict):
            raise ValueError("RAES runtime snapshot entry is invalid")
        if not entry.get("profile_bindings"):
            entry.pop("profile_bindings", None)
        if entry.get("resource_type") != "account-placement":
            continue
        account_payload = entry.get("payload")
        if account_placement_has_credential_bindings(account_payload):
            entry["payload"] = value_free_account_placement_payload(account_payload)
    return {"schema_version": RuntimeSnapshotEnvelope().schema_version, **payload}


def build_reproducibility_record(inputs: RunRecordInputs) -> dict[str, Any]:
    """Build a REP-001 run reproducibility record dict.

    Anchors RAES-contract identity at ``record["raes"]`` and carries APTL
    backend realization evidence at ``record["backend_evidence"]``. Emits
    schema v2 only; v1 records (which used ``record["raes"]``) are still
    readable but are never produced.
    """
    manifest = create_aptl_manifest()
    manifest_payload = backend_manifest_payload(manifest)
    runtime_snapshot_payload = runtime_snapshot_record_payload(inputs.final_snapshot)
    raes_lock_digest = _raes_lock_digest(inputs.scenario_path)

    scenario_section: dict[str, Any] = {
        "sdl_path": str(inputs.scenario_path) if inputs.scenario_path else None,
        "display_name": inputs.scenario_display_name,
        "raes_lock_digest": raes_lock_digest,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": inputs.run_id,
        "backend_name": inputs.backend_name,
        "backend_manifest_version": manifest_payload.get("schema_version", ""),
        "started_at": inputs.started_at,
        "finished_at": inputs.finished_at,
        "outcome": inputs.outcome,
        CONTRACT_SECTION: {
            "backend_manifest": manifest_payload,
            "runtime_snapshot": runtime_snapshot_payload,
            "scenario": scenario_section,
            "scenario_parameters": None,
            "scenario_parameters_note": _PARAMETERS_OMITTED_NOTE,
            "realization": inputs.realization_details,
        },
        "backend_evidence": {
            "selected_profiles": inputs.selected_profiles,
            "pack_interaction": inputs.pack_interaction_evidence,
            "range_snapshot": inputs.range_snapshot_dict,
            "config_digests": inputs.config_digests,
            "container_image_digests": inputs.container_image_digests,
            "detection_content_digest": inputs.detection_content_digest,
            "tool_versions": inputs.tool_versions,
            "evidence_references": inputs.evidence_references,
        },
    }


def _raes_lock_digest(scenario_path: Path | None) -> str | None:
    """Compute the sha256 of the module lockfile adjacent to scenario_path.

    The lockfile name is upstream-owned and read from RAES rather than
    hardcoded: RAES 2.0.0 publishes it as ``raes.lock.json``, and APTL tracks
    that upstream contract through the imported constant.
    """
    if scenario_path is None:
        return None
    lock_path = scenario_path.parent / LOCKFILE_NAME
    if not lock_path.exists():
        return None
    return hashlib.sha256(lock_path.read_bytes()).hexdigest()
