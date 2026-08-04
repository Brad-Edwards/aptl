---
id: RNG-003
title: "Snapshot/Restore for Mid-Scenario Checkpointing"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:50:17.358990Z
updated_at: 2026-03-21T07:50:17.358990Z
---

# RNG-003: Snapshot/Restore for Mid-Scenario Checkpointing

## Statement

The platform shall support snapshotting the complete range state (container filesystems, volumes, network state) at arbitrary points during scenario execution, and restoring from those snapshots for replay, branching, or recovery.

## Rationale

SCN-005 captures range snapshots but only for metadata (versions, rules inventory). Full state snapshot/restore enables what-if analysis, checkpoint/restart for long exercises, and deterministic replay.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#453` (RNG-003: Snapshot/Restore for Mid-Scenario Checkpointing)
