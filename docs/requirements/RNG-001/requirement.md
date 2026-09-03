---
id: RNG-001
title: "Ephemeral Environments with Clean State Guarantees"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-21T07:50:09.245639Z
updated_at: 2026-06-25T05:16:42.671257Z
---

# RNG-001: Ephemeral Environments with Clean State Guarantees

## Statement

The platform shall support ephemeral environments that guarantee clean state between runs, tearing down and recreating containers to eliminate state contamination from prior exercises.

## Rationale

Persistent containers accumulate state (files, processes, credentials, logs) that contaminate subsequent runs. Clean-state guarantees are prerequisite for reliable batch execution and benchmarking.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#424` (RNG-001: Ephemeral Environments with Clean State Guarantees)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (clean_boot_lab lifecycle mode)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/lab.py` (aptl lab start --clean CLI surface)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_live_gate_probes.py` (live gate consumes clean_boot_lab)
- TESTS → TEST `tests/test_lab.py` (TestCleanBootLab)
- TESTS → TEST `tests/test_cli.py` (start --clean CLI tests)
- TESTS → TEST `tests/test_techvault_live_gate.py` (live-gate boot tests (clean_boot_lab))
- IMPLEMENTS → GITHUB_ISSUE `424` (RNG-001: Ephemeral Environments with Clean State Guarantees)
- DOCUMENTS → DOCUMENTATION `docs/reference/experiment-runs.md` (Clean State Between Runs reference)
