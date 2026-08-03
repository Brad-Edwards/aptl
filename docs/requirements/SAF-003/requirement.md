---
id: SAF-003
title: "Tiered Autonomy Levels"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:50:57.939809Z
updated_at: 2026-03-21T07:50:57.939809Z
---

# SAF-003 — Tiered Autonomy Levels

## Statement

The platform shall support configurable autonomy tiers for agent operations: observe (read-only reconnaissance), investigate (non-destructive queries and analysis), execute (run pre-approved actions with confirmation), and autonomous (full independent operation within safety bounds).

## Rationale

NVIDIA recommends tiered isolation. Different use cases (training, research, benchmarking) require different levels of agent freedom. One-size-fits-all autonomy is either too restrictive or too dangerous.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#455` (SAF-003 — Tiered Autonomy Levels)
