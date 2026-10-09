---
id: DSL-007
title: "Cleanup and Rollback Definitions in Scenarios"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:43.388542Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# DSL-007: Cleanup and Rollback Definitions in Scenarios

## Statement

The scenario DSL shall support cleanup and rollback definitions that specify how to reverse scenario effects (remove implants, restore files, reset credentials) for environment reuse without full teardown.

## Rationale

Without cleanup definitions, environments must be fully rebuilt between runs. Atomic Red Team includes cleanup_command per test. Cleanup definitions enable faster iteration and reduce the dependency on ephemeral environments for every run.

NOT DEPRECATED 2026-10-09: ADR-035 deprecates DSL-002 to DSL-009, but open issue #435 still tracks this record. On 2026-07-03 the issue moved the cleanup contract to RAES (rae#658) and kept only the LilRAE realization. No other record covers declared cleanup or rollback: the cleanup in RNG-001, DEP-003 and SEC-008 tears down the whole lab. See GitHub issue #435.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#435` (DSL-007: Cleanup and Rollback Definitions in Scenarios)
