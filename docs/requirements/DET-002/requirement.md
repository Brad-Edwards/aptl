---
id: DET-002
title: "Closed-Loop Detection Rule Auto-Generation"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:49:43.004884Z
updated_at: 2026-03-21T07:49:43.004884Z
---

# DET-002 — Closed-Loop Detection Rule Auto-Generation

## Statement

When a scenario attack technique is executed but not detected, the platform shall auto-generate candidate detection rules (in Sigma format) covering the missed technique, enabling a closed-loop detection engineering workflow.

## Rationale

CTEM requires closed-loop: attack → check detection → generate rule for gap → deploy → re-validate. No commercial BAS platform fully automates this loop. This would be a significant differentiator.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#431` (DET-002 — Closed-Loop Detection Rule Auto-Generation)
