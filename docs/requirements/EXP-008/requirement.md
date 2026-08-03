---
id: EXP-008
title: "Portable Research Evidence Bundle Export"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 3
created_at: 2026-03-24T02:42:29.070052Z
updated_at: 2026-07-29T00:16:18.402084Z
---

# EXP-008 — Portable Research Evidence Bundle Export

## Statement

APTL shall export a sealed, self-describing evidence bundle containing canonical ACES task/spec/run/apparatus/capture/evidence artifacts, referenced raw observations, schema and contract versions, checksums, sensitivity and redaction disclosures, collection limitations, and a machine-readable inventory/data dictionary. JSONL and Parquet projections and OCSF-aligned event projections may be included only where the mapping is loss-accounted and source records remain referenced. Export shall be deterministic, path-contained, integrity-verifiable, and safe against formula/path injection. It shall not perform statistical analysis, select publication claims, or certify a dataset as publishable.

## Rationale

Researchers need interoperable evidence, not an APTL opinion about analysis or publication readiness. A faithful bundle reduces extraction work while leaving research design, transformation, and analysis downstream.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#472` (EXP-008 — Portable research evidence bundle export)
- TESTS → TEST `tests/test_evidence_bundle_fuzz.py`
- IMPLEMENTS → GITHUB_ISSUE `472`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/build.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/closure.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/_collect.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/archive.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/verify.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/inventory.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/envelope.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/schemas.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/models.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/projections/registry.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/projections/jsonl.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/projections/parquet.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence_bundle/projections/ocsf.py`
- IMPLEMENTS → CODE_FILE `src/aptl/cli/runs.py`
- IMPLEMENTS → CODE_FILE `src/aptl/utils/deterministic_archive.py`
- IMPLEMENTS → DOCUMENTATION `docs/reference/evidence-bundle-export.md`
- TESTS → TEST `tests/test_evidence_bundle_closure.py`
- TESTS → TEST `tests/test_evidence_bundle_archive.py`
- TESTS → TEST `tests/test_evidence_bundle_projections.py`
- TESTS → TEST `tests/test_evidence_bundle_verify.py`
- TESTS → TEST `tests/test_evidence_bundle_security.py`
- TESTS → TEST `tests/test_evidence_bundle_cli.py`
- TESTS → TEST `tests/test_evidence_bundle_inventory.py`
