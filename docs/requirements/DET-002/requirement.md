---
id: DET-002
title: "Closed-Loop Detection Rule Auto-Generation"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 2
created_at: 2026-03-21T07:49:43.004884Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# DET-002: Closed-Loop Detection Rule Auto-Generation

## Statement

When a scenario attack technique is executed but not detected, the platform shall auto-generate candidate detection rules (in Sigma format) covering the missed technique, enabling a closed-loop detection engineering workflow.

## Rationale

WITHDRAWN 2026-10-09: The issue closed as not planned on 2026-07-19 without a closing comment. See GitHub issue #431. --- Original rationale: CTEM requires closed-loop: attack → check detection → generate rule for gap → deploy → re-validate. No commercial BAS platform fully automates this loop. This would be a significant differentiator.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#431` (DET-002: Closed-Loop Detection Rule Auto-Generation)
