---
id: REP-001
title: "ACES-Aligned Run Reproducibility Record"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-21T07:52:48.239319Z
updated_at: 2026-06-25T16:18:21.506620Z
---

# REP-001 — ACES-Aligned Run Reproducibility Record

## Statement

The platform shall capture an ACES-aligned reproducibility record for every run, preserving scenario snapshot identity, ACES processor/backend manifest identity, runtime snapshot/provenance, apparatus and realization details, image and configuration digests, detection-content versions, tool versions, scenario parameters, seeds, and evidence references needed to reproduce or audit the run. APTL run-archive fields may store backend-specific evidence, but the canonical structure shall align with ACES task, run, apparatus, evidence, and provenance contracts where those contracts exist.

## Rationale

The TechVault cutover moved scenario and experiment meaning to ACES. Reproducibility should therefore be anchored in ACES task/run/apparatus/provenance surfaces, with APTL recording realization evidence as a backend, rather than defining a parallel APTL-only experiment manifest.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#423` (REP-001 — Experiment Manifest for Reproducibility)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Lab lifecycle — triggers repro record capture on run start/stop)
- IMPLEMENTS → CODE_FILE `src/aptl/core/snapshot.py` (Snapshot capture — provides scenario snapshot identity for repro record)
- TESTS → TEST `tests/test_lab.py` (Lab lifecycle tests — covers repro record capture invocation paths)
- TESTS → TEST `tests/test_runstore.py` (Run store tests — covers run archive/storage that backs repro record persistence)
- TESTS → TEST `tests/test_snapshot.py` (Snapshot tests — covers snapshot identity fields consumed by repro record)
- IMPLEMENTS → GITHUB_ISSUE `423` (Issue #423: REP-001 — ACES-aligned run reproducibility record)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_repro.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes.py`
- IMPLEMENTS → ADR `docs/adrs/adr-044-raes-aligned-run-reproducibility-record.md`
- TESTS → TEST `tests/test_raes_repro.py`
- TESTS → TEST `tests/test_raes_backend.py`
