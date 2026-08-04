---
id: EXP-010
title: "Capture Plan Admission and Evidence Acquisition"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-07-11T02:30:43.480323Z
updated_at: 2026-07-20T22:36:07.446940Z
---

# EXP-010: Capture Plan Admission and Evidence Acquisition

## Statement

APTL shall consume ACES experiment-capture-spec-v1 artifacts and compare their required sources, scopes, windows, formats, and fidelity constraints with declared backend observation capabilities before execution. Admission shall produce a versioned capture plan. Unsupported required capture shall fail closed; optional degradation shall require an explicit limitation and comparability disclosure. Pluggable collectors shall emit raw experiment-evidence-record-v1 artifacts with source, clock, loss, sensitivity, checksum, and provenance metadata and shall never expose participant-hidden or secret-bearing data outside the authorized capture boundary.

## Rationale

A research apparatus must know before a trial whether it can observe what the protocol requires. Capture capability negotiation and raw evidence provenance prevent silent missing data, invented completeness, and backend-private collector formats.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `Brad-Edwards/aptl#752` (EXP-010: Capture plan admission and evidence acquisition)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/capture_registry.py` (Collector registry: deterministic capture-requirement match + observation projection)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/capture_mapping.py` (bind_capture_requirements: registry-backed fail-closed admission entry point)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/trial_plan.py` (Capture bindings pinned into the canonical trial-plan bytes (schema v2))
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/policy.py` (CaptureLimitationAcceptance: required-by-default capture + auditable degradation)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/admission.py` (admit_experiment: bind capture requirements against the registry and pin into the plan)
- IMPLEMENTS → PULL_REQUEST `Brad-Edwards/aptl#810` (EXP-010 PR 1 of 2: capture-admission foundation)
- TESTS → TEST `tests/test_capture_registry.py` (Registry: ID validation, 11-axis match, determinism, observation projection)
- TESTS → TEST `tests/test_manifest_observation.py` (Manifest observation: honest-None default + populated-projection contract-gap invariant)
- TESTS → TEST `tests/test_experiment_capture_mapping.py` (bind_capture_requirements: fail-closed baseline, success path, degradation)
- TESTS → TEST `tests/test_experiment_admission.py` (End-to-end admitted-capture path + zero-mutation fail-closed)
- TESTS → TEST `tests/test_experiment_trial_plan.py` (Capture-binding pinning + determinism in the canonical trial plan)
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence/coordinator.py` (Evidence coordinator: start/run/stop-in-finally + terminal-semantics dispositions)
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence/content_store.py` (Content-addressed streaming + run-scoped create-once persistence (quotas, no-follow, digest verify))
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence/records.py` (ACES experiment-evidence-record-v1 construction with content-derived identity)
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence/_persist.py` (Per-outcome persistence: media check, structured redaction, limit enforcement, evidence ledger)
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence/protocol.py` (Narrow Collector protocol + immutable CollectorContext/RunScope (no controller/store/paths))
- IMPLEMENTS → CODE_FILE `src/aptl/core/evidence/adapters/sources.py` (Windowed-query collector framework distinguishing source failure from legitimate emptiness)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/capture_registrations.py` (The 5 trusted built-in collector registrations: turns manifest observation on)
- IMPLEMENTS → PULL_REQUEST `Brad-Edwards/aptl#811` (EXP-010 PR 2 of 2: evidence acquisition)
- TESTS → TEST `tests/test_evidence_coordinator.py` (Coordinator: terminal dispositions, reverse-order stop, limit enforcement, key scoping, trial-body lifecycle)
- TESTS → TEST `tests/test_evidence_records.py` (Evidence records: identity determinism + ACES conformance round-trip + loss disclosure)
- TESTS → TEST `tests/test_evidence_security.py` (Secret redaction in stored bytes, participant-visibility projection, hostile symlink fails closed)
- TESTS → TEST `tests/test_evidence_correlation.py` (Acquired evidence refs integrate with the #447 correlation projection)
- TESTS → TEST `tests/test_runstore_content_store.py` (Content-addressed persistence: quotas during streaming, no-follow, digest verify, idempotency)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_manifest.py`
