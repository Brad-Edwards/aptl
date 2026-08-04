---
id: DEP-003
title: "Ephemeral Environment Lifecycle"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 3
created_at: 2026-03-21T07:53:48.031381Z
updated_at: 2026-06-28T17:23:29.158157Z
---

# DEP-003: Ephemeral Environment Lifecycle

## Statement

The platform shall support automated provisioning and teardown of complete range instances on demand, with defined lifecycle policies (TTL-based auto-teardown, idle detection, scheduled provisioning).

## Rationale

Manual provisioning and teardown doesn't scale for training programs, CI/CD integration, or benchmark suites. Ephemeral lifecycle is the dominant strategy for cloud-based cyber ranges to manage cost and prevent state accumulation.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/core/lifecycle_policy.py` (Lifecycle policy model + pure evaluators + state (DEP-003))
- IMPLEMENTS → CODE_FILE `src/aptl/core/lifecycle_enforce.py` (Lifecycle enforcement runtime: enforce_once/run_monitor (DEP-003))
- IMPLEMENTS → CODE_FILE `src/aptl/cli/lifecycle.py` (CLI: aptl lab enforce/monitor/policy show (DEP-003))
- IMPLEMENTS → CONFIG `src/aptl/core/config.py` (LabLifecyclePolicyConfig / LifecycleScheduleEntry schema (DEP-003))
- IMPLEMENTS → ADR `docs/adrs/adr-045-ephemeral-lifecycle-policy-enforcement.md` (ADR-045: Ephemeral Lifecycle Policy Enforcement)
- TESTS → TEST `tests/test_lifecycle_policy.py` (Unit tests: evaluators, state, enforce_once/run_monitor (DEP-003))
- TESTS → TEST `tests/test_cli_lifecycle.py` (CLI wiring tests for lifecycle commands (DEP-003))
- IMPLEMENTS → GITHUB_ISSUE `467` (DEP-003: Ephemeral Environment Lifecycle)
