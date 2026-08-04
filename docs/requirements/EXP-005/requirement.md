---
id: EXP-005
title: "Safe Experimental Parameter Binding and Provenance"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-24T02:42:00.205125Z
updated_at: 2026-07-27T15:37:03.190777Z
---

# EXP-005: Safe Experimental Parameter Binding and Provenance

## Statement

APTL shall bind each admitted experimental condition only to explicitly supported parameter surfaces: ACES scenario instantiation parameters, ACES participant-implementation configuration, or allowlisted APTL apparatus configuration. Unknown parameters, cross-plane injection, type mismatches, and attempts to bind secrets as values shall fail admission. Each run shall record the realized non-secret values, source factor and condition, binding target, and configuration digest; secret references shall be recorded by non-sensitive identity only. Prompt or interaction-content capture shall be opt-in through an ACES capture specification and sensitivity policy, not an implicit APTL feature.

## Rationale

Parameterized experiments are essential, but prompt templating and provider behavior belong to ACES participant implementations. APTL must safely realize declared factors across its backend surfaces and preserve exact, redaction-aware provenance without becoming an agent runtime.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#441` (EXP-005: Safe experimental parameter binding and provenance)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/bindings.py` (Canonical experiment parameter binding)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/admission.py` (Experiment admission integration)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/admission_artifacts.py` (Admission participant manifest resolution)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/trial_plan_models.py` (Canonical trial-plan binding projection)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_manifest.py` (RAES apparatus target registry)
- IMPLEMENTS → CODE_FILE `src/aptl/core/config.py` (Allowlisted typed experiment configuration)
- TESTS → TEST `tests/test_experiment_bindings.py` (Experiment binding safety and provenance tests)
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/trial_plan.py` (Deterministic trial-plan binding and provenance)
- TESTS → TEST `tests/test_experiment_controller.py` (Experiment controller binding integration tests)
- TESTS → TEST `tests/test_experiment_admission.py` (Fail-closed admission and manifest tests)
- TESTS → TEST `tests/test_experiment_cli.py` (Experiment CLI binding diagnostics tests)
- TESTS → TEST `tests/test_raes_backend.py` (RAES target-registry tests)
- DOCUMENTS → DOCUMENTATION `docs/architecture/exp-005-safe-parameter-binding-provenance-preflight.md` (EXP-005 safe binding and provenance architecture)
- DOCUMENTS → ADR `docs/adrs/adr-047-raes-experiment-admission-and-trial-plan-boundary.md` (RAES experiment admission and trial-plan boundary ADR)
- IMPLEMENTS → GITHUB_ISSUE `441` (Issue #441: safe parameter binding)
