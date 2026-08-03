---
id: AGT-003
title: "Persistent Cross-Session Agent Memory"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:49:04.733391Z
updated_at: 2026-06-28T17:13:17.532880Z
---

# AGT-003 — Persistent Cross-Session Agent Memory

## Statement

The platform shall provide persistent agent memory that survives across sessions, storing discovered facts (credentials, network topology, host fingerprints, vulnerability findings) accessible to subsequent runs. ACES scope constraint (ADR-035 / SCN-010): discovered facts and environment state are owned by the ACES dynamic-knowledge / environment-state semantics (ACT-604, aces#212) and participant-consumable derived-context views (ACT-616, aces#250); memory shall be stored in / projected from those ACES contracts and read back via them, NOT a private APTL knowledge store that becomes a parallel source of truth. Dependency: blocked on ACES ACT-604 / ACT-616 (open/unbuilt upstream) and on the APTL AGT-001 orchestration layer to bind memory into.

## Rationale

PentAGI uses long-term memory for multi-session campaigns. Without persistence, each run starts from zero, preventing cumulative learning and realistic multi-day adversary simulation.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#425` (AGT-003 — Persistent Cross-Session Agent Memory)
