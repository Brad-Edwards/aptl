---
id: REP-003
title: "Run-Scoped Apparatus and Detection-Content Provenance"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-21T07:52:56.533890Z
updated_at: 2026-07-28T17:38:03.665415Z
---

# REP-003: Run-Scoped Apparatus and Detection-Content Provenance

## Statement

At each run seal point APTL shall record the selected ACES processor, backend, participant-implementation, and capability manifests; canonical scenario snapshot; APTL configuration identity; image and dependency digests; detector/rule/policy content digests; collector and tool versions; range snapshot identity; and relevant host/runtime inventory. Collection shall reuse DeploymentBackend, RangeSnapshot, ACES manifest, and existing inventory owners. Secret values, rendered secret-bearing configuration, private keys, tokens, cookies, and raw environment dumps shall never enter the provenance record.

## Rationale

APTL is the experimental apparatus, so its realized form is a scientific variable. Broad run-scoped provenance supersedes detection-rule-only versioning and allows later users to assess reproducibility and comparability without exposing credentials.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#452` (REP-003: Run-scoped apparatus and detection-content provenance)
- DOCUMENTS → DOCUMENTATION `docs/reference/experiment-runs.md` (Run-archive provenance record reference: fields, limitations, and secret exclusions)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/coordinator.py` (Bounded provenance collection coordinator: enforces limits, normalizes failures into typed outcomes)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/identity.py` (Domain-separated canonical identity: per-artifact leaf framing and family folding)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/registry.py` (Capability-declared provenance provider registry and seal profile)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/record.py` (Create-once ready-to-seal and provisional run provenance record publication)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/registrations.py` (Built-in provider fleet declarations and default seal profile)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/outcomes.py` (Closed outcome vocabulary and explicit limitation reason codes)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/protocol.py` (Narrow provider seam: context, deadline, and typed result contract)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/detection.py` (Detector rule, policy, and allowlist content provenance with contained no-follow reads)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/apparatus.py` (RAES processor and backend manifest identity from owner-native serializers)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/experiment.py` (Admitted scenario snapshot, trial, and capture-binding collector identity)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/participant.py` (Participant implementation manifest, selection, and model identity provenance)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/config_identity.py` (Versioned safe effective-config projection excluding secrets and credential locators)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/runtime_facts.py` (Image digests, tool versions, range snapshot identity, and bounded host facts)
- IMPLEMENTS → CODE_FILE `src/aptl/core/provenance/providers/artifacts.py` (Dependency and participant asset lock digests from the locks actually present)
- IMPLEMENTS → CODE_FILE `src/aptl/core/snapshot.py` (Corrected detection-content identity and removal of .env from config hashing)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Lab lifecycle wiring: publishes provisional run provenance at startup)
- TESTS → TEST `tests/test_provenance_identity.py` (Identity framing, digest normalization, and concatenation-collision regression)
- TESTS → TEST `tests/test_provenance_outcomes.py` (Closed status vocabulary and stable limitation reason codes)
- TESTS → TEST `tests/test_provenance_registry.py` (Provider declaration bounds, non-executable IDs, and seal-profile validation)
- TESTS → TEST `tests/test_provenance_coordinator.py` (Bounded collection, failure normalization, payload ceilings, and determinism)
- TESTS → TEST `tests/test_provenance_detection.py` (Detection surface coverage, targeted differences, symlink and secret exclusion)
- TESTS → TEST `tests/test_provenance_apparatus.py` (Apparatus manifest, admitted experiment, and participant selection provenance)
- TESTS → TEST `tests/test_provenance_config_runtime.py` (Safe config projection exclusions and identity-versus-observation separation)
- TESTS → TEST `tests/test_provenance_artifacts_host.py` (Dependency lock digests, collector/channel identity, and bounded host facts)
- TESTS → TEST `tests/test_provenance_record.py` (Create-once publication, conflict fail-closed, and secret-invariant refusal)
- TESTS → TEST `tests/test_provenance_builtin_fleet.py` (Built-in fleet composition, honest unavailable reporting, and end-to-end publication)
- TESTS → TEST `tests/test_provenance_review_fixes.py` (Seal-boundary ownership, stable range identity, and explicit allowlist regressions)
- TESTS → TEST `tests/test_snapshot.py` (Corrected detection-content digest coverage and .env exclusion from config hashes)
- IMPLEMENTS → DOCUMENTATION `docs/architecture/rep-003-run-scoped-provenance-preflight.md` (REP-003 architecture preflight: binding boundaries, incumbents, and guardrails)
- IMPLEMENTS → GITHUB_ISSUE `452` (Issue #452: REP-003: Run-scoped apparatus and detection-content provenance)
- IMPLEMENTS → PULL_REQUEST `871` (PR #871: feat: record run-scoped apparatus and detection-content provenance)
