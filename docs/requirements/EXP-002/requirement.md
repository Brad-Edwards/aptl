---
id: EXP-002
title: "ACES Experiment Specification Admission and Trial Planning"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-24T02:41:59.832639Z
updated_at: 2026-07-20T03:49:54.664825Z
---

# EXP-002 — ACES Experiment Specification Admission and Trial Planning

## Statement

APTL shall consume ACES experiment-authoring-input-v1 specifications and their referenced experiment-task-v1, capture-spec, and scenario artifacts through published ACES contract APIs. Admission shall validate closed-world structure, ACES semantic invariants, artifact identities and digests, supported contract versions, apparatus constraints, and backend capabilities before expanding the run allocation into a deterministic immutable trial plan with stable run identities, condition assignments, stochastic controls, and execution controls. APTL shall not define a private experiment protocol, task, study, or analysis schema.

## Rationale

APTL is the execution apparatus for ACES-authored experiments. Contract admission and deterministic planning are required to support parameterized research without duplicating ACES scientific semantics or allowing unvalidated experiment input to control the range.

## Traceability

- TESTS → TEST `tests/test_experiment_errors.py`
- TESTS → TEST `tests/test_experiment_persistence.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/admission.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/admission_artifacts.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/admission_steps.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/apparatus.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/capture_mapping.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/controller.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/errors.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/policy.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/resolver.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/spec_loading.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/experiment/trial_plan.py`
- IMPLEMENTS → CODE_FILE `src/aptl/cli/experiment.py`
- IMPLEMENTS → CODE_FILE `src/aptl/utils/pathsafe.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/runstore.py`
- IMPLEMENTS → CODE_FILE `src/aptl/utils/redaction.py`
- TESTS → TEST `tests/test_experiment_policy.py`
- TESTS → TEST `tests/test_experiment_resolver.py`
- TESTS → TEST `tests/test_experiment_spec_loading.py`
- TESTS → TEST `tests/test_experiment_trial_plan.py`
- TESTS → TEST `tests/test_pathsafe.py`
- IMPLEMENTS → GITHUB_ISSUE `#438`
- TESTS → TEST `tests/test_experiment_admission.py`
- TESTS → TEST `tests/test_experiment_apparatus.py`
- TESTS → TEST `tests/test_experiment_capture_mapping.py`
- TESTS → TEST `tests/test_experiment_cli.py`
- TESTS → TEST `tests/test_experiment_contract.py`
- TESTS → TEST `tests/test_experiment_controller.py`
- TESTS → TEST `tests/test_raes_diagnostics.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_diagnostics.py`
- IMPLEMENTS → ADR `docs/adrs/adr-047-raes-experiment-admission-and-trial-plan-boundary.md`
