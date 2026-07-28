"""Shared fixtures for the EXP-008 evidence-bundle tests.

Builds a realistic ``ready-to-seal`` run tree on disk (the pre-#444 state the
closure builder must consume): RAES evidence records + their content-addressed
blobs, REP-003 provenance, OBS-002 correlation, and the run manifest. Named
without a ``test_`` prefix so pytest does not collect it as a test module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import rfc8785
from raes_contracts.contracts import (
    ExperimentCaptureSpecReferenceModel,
    ExperimentChecksumModel,
    ExperimentEvidenceRecordModel,
    ExperimentReferenceModel,
)
from raes_contracts.contracts.experiment_capture import (
    ExperimentRawEvidenceContentModel,
)


@dataclass(frozen=True)
class WrittenEvidence:
    record_id: str
    record_relpath: str
    blob_relpath: str
    blob_bytes: bytes
    sensitivity: str
    redaction_state: str
    visibility: str


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_evidence_record(
    *,
    run_id: str,
    blob_bytes: bytes,
    sensitivity: str = "restricted",
    redaction_state: str = "none",
    loss_disclosure: str | None = None,
    requirement_id: str = "req-1",
    capture_spec_id: str = "spec-1",
    evidence_kind: str = "log",
    captured_at: str = "2026-03-24T02:42:29Z",
    content_uri: str | None = None,
) -> ExperimentEvidenceRecordModel:
    content_hex = _digest(blob_bytes)
    identity = {
        "domain": "aptl.exp.evidence-record/v1",
        "run_id": run_id,
        "requirement_id": requirement_id,
        "capture_spec_id": capture_spec_id,
        "content_digest": f"sha256:{content_hex}",
    }
    record_id = "evidence-" + hashlib.sha256(rfc8785.dumps(identity)).hexdigest()
    blob_relpath = (
        content_uri if content_uri is not None else f"evidence/blobs/{content_hex}"
    )
    return ExperimentEvidenceRecordModel(
        schema_version="experiment-evidence-record/v1",
        evidence_record_id=record_id,
        record_version="1.0.0",
        capture_spec_ref=ExperimentCaptureSpecReferenceModel(
            ref_kind="capture-spec", ref_id=capture_spec_id
        ),
        capture_requirement_ref=requirement_id,
        run_ref=ExperimentReferenceModel(ref_kind="run", ref_id=run_id),
        source_refs=[
            ExperimentReferenceModel(
                ref_kind="measurement-channel", ref_id="channel-1", ref_version="1"
            )
        ],
        evidence_kind=evidence_kind,
        captured_at=captured_at,
        capture_window_ref=requirement_id,
        raw_content=ExperimentRawEvidenceContentModel(
            content_uri=blob_relpath,
            content_checksum=ExperimentChecksumModel(
                algorithm="sha256", value=content_hex
            ),
            payload_summary=f"1 event(s), {len(blob_bytes)} byte(s) retained",
            loss_disclosure=loss_disclosure,
        ),
        sensitivity=sensitivity,
        redaction_state=redaction_state,
    )


def write_evidence(
    run_dir: Path,
    *,
    run_id: str,
    blob_bytes: bytes = b'{"event": 1, "id": "007", "big": 9223372036854775807}\n',
    visibility: str = "disclosed",
    **kwargs: object,
) -> WrittenEvidence:
    """Write one evidence record + its blob into ``run_dir`` and return refs."""
    record = build_evidence_record(run_id=run_id, blob_bytes=blob_bytes, **kwargs)
    blob_relpath = record.raw_content.content_uri
    record_relpath = f"evidence/records/{record.evidence_record_id}.json"
    (run_dir / "evidence" / "blobs").mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence" / "records").mkdir(parents=True, exist_ok=True)
    (run_dir / blob_relpath).write_bytes(blob_bytes)
    (run_dir / record_relpath).write_bytes(
        rfc8785.dumps(record.model_dump(mode="json", exclude_none=True))
    )
    return WrittenEvidence(
        record_id=record.evidence_record_id,
        record_relpath=record_relpath,
        blob_relpath=blob_relpath,
        blob_bytes=blob_bytes,
        sensitivity=record.sensitivity,
        redaction_state=record.redaction_state,
        visibility=visibility,
    )


def write_provenance(
    run_dir: Path, *, run_id: str, seal_state: str = "ready-to-seal"
) -> str:
    relpath = "provenance/run-provenance.json"
    record = {
        "schema_version": "aptl.run-provenance/v1",
        "run_id": run_id,
        "seal_state": seal_state,
        "aggregate_identity": "sha256:" + _digest(run_id.encode()),
        "registry_declaration_digest": "sha256:" + _digest(b"registry"),
        "sections": [],
        "limitations": [],
    }
    (run_dir / "provenance").mkdir(parents=True, exist_ok=True)
    (run_dir / relpath).write_bytes(rfc8785.dumps(record))
    return relpath


def write_correlation(run_dir: Path, *, run_id: str) -> str:
    relpath = "correlation.json"
    projection = {
        "schema_version": "aptl-correlation/v1",
        "run_id": run_id,
        "nodes": [],
        "edges": [],
        "clock_contexts": [],
        "disclosures": [],
    }
    (run_dir / relpath).write_bytes(rfc8785.dumps(projection))
    return relpath


def write_ocsf(run_dir: Path, *, rows: list[dict] | None = None) -> str:
    relpath = "mcp-side/ocsf.jsonl"
    rows = rows if rows is not None else [{"class_uid": 1001, "activity_id": 1}]
    (run_dir / "mcp-side").mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(row) + "\n" for row in rows)
    (run_dir / relpath).write_text(body, encoding="utf-8")
    return relpath


def write_manifest(run_dir: Path, *, run_id: str) -> str:
    relpath = "manifest.json"
    manifest = {
        "run_id": run_id,
        "scenario_id": "techvault",
        "scenario_name": "TechVault",
        "started_at": "2026-03-24T02:00:00Z",
        "finished_at": "2026-03-24T02:42:29Z",
    }
    (run_dir / relpath).write_text(json.dumps(manifest), encoding="utf-8")
    return relpath


def build_ready_to_seal_run(
    run_dir: Path, *, run_id: str = "run-1", evidence_count: int = 1
) -> list[WrittenEvidence]:
    """Populate ``run_dir`` with a full ready-to-seal artifact set."""
    run_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(run_dir, run_id=run_id)
    write_provenance(run_dir, run_id=run_id)
    write_correlation(run_dir, run_id=run_id)
    written: list[WrittenEvidence] = []
    for index in range(evidence_count):
        written.append(
            write_evidence(
                run_dir,
                run_id=run_id,
                blob_bytes=f'{{"event": {index}, "id": "00{index}"}}\n'.encode(),
                requirement_id=f"req-{index}",
                capture_spec_id=f"spec-{index}",
            )
        )
    return written
