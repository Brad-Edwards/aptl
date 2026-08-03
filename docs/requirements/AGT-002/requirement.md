---
id: AGT-002
title: "ACES-Aligned Multi-Agent Coordination"
status: DRAFT
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-21T07:49:00.755641Z
updated_at: 2026-06-22T01:20:43.682776Z
---

# AGT-002 — ACES-Aligned Multi-Agent Coordination

## Statement

The platform shall support concurrent operation of multiple ACES-declared participants or agents - at minimum red and blue roles - with a purple-team coordinator that observes portable workflow/evaluation state, records coordination events, and measures detection/response coverage without using APTL-private participant semantics as the source of truth.

## Rationale

Purple-team research still requires simultaneous offense and defense, but the coordination model must be layered on ACES participant and runtime contracts. Moving this out of Wave 1 avoids treating broad multi-agent behavior as a prerequisite for the TechVault authoring cutover.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#420` (AGT-002 — Multi-Agent Coordination (Red + Blue Concurrent))
