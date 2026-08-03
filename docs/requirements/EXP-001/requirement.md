---
id: EXP-001
title: "Durable Experiment Execution and Fault Recovery"
status: DRAFT
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-22T05:36:30.464088Z
updated_at: 2026-07-11T02:30:28.880925Z
---

# EXP-001 — Durable Experiment Execution and Fault Recovery

## Statement

APTL shall execute an admitted trial plan through a durable, versioned campaign journal and explicit state machine. It shall classify failures as infrastructure, apparatus-readiness, participant, scenario, capture, operator-cancelled, or policy/budget failures; preserve all evidence available at interruption; and retry only configured retryable classes within bounded attempt and backoff budgets. Each attempt shall have a distinct archival run identity with lineage to the planned trial and prior attempt. Restart after process or host failure shall be idempotent and shall not duplicate completed trials or reuse contaminated range state.

## Rationale

Unattended research runs require recovery that is scientifically auditable. A durable state machine, bounded retry policy, and attempt lineage provide reliability without hiding deterministic failures or rewriting one archival ACES run in place.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#437` (EXP-001 — Durable experiment execution and fault recovery)
