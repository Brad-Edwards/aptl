---
id: SIM-004
title: "Campaign Pause, Resume, and Controlled Re-execution"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 3
created_at: 2026-03-21T07:53:25.174643Z
updated_at: 2026-07-11T02:30:30.746064Z
---

# SIM-004 — Campaign Pause, Resume, and Controlled Re-execution

## Statement

APTL shall allow a campaign to stop admitting trials, pause at a safe trial boundary, resume from its durable journal, and re-execute a selected sealed trial specification as a new run with explicit lineage. Mid-trial checkpoint/restore may be offered only when the active backend advertises and validates that capability; otherwise it shall be rejected rather than simulated. Re-execution shall preserve available inputs and disclose changed or unavailable artifacts, apparatus, secrets, and external dependencies. APTL shall not claim bit-exact replay.

## Rationale

Campaign-level control and auditable re-execution are achievable and useful. Container freezing or exact replay is backend-dependent and scientifically misleading unless all hidden state and external dependencies are controlled.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#499` (SIM-004 — Campaign pause, resume, and controlled re-execution)
