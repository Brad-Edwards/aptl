---
id: DSL-007
title: "Cleanup and Rollback Definitions in Scenarios"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:43.388542Z
updated_at: 2026-03-21T07:52:43.388542Z
---

# DSL-007: Cleanup and Rollback Definitions in Scenarios

## Statement

The scenario DSL shall support cleanup and rollback definitions that specify how to reverse scenario effects (remove implants, restore files, reset credentials) for environment reuse without full teardown.

## Rationale

Without cleanup definitions, environments must be fully rebuilt between runs. Atomic Red Team includes cleanup_command per test. Cleanup definitions enable faster iteration and reduce the dependency on ephemeral environments for every run.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#435` (DSL-007: Cleanup and Rollback Definitions in Scenarios)
