---
id: AGT-001
title: "ACES-Aligned Agent Orchestration Layer"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-21T07:48:56.306563Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# AGT-001: ACES-Aligned Agent Orchestration Layer

## Statement

The platform shall provide an agent orchestration layer that consumes ACES scenario, runtime, participant, orchestration, and evaluation surfaces, instantiates configured LLM-backed or scripted agents, invokes APTL/MCP tools under declared authority and scope, observes portable workflow/evaluation state, and adapts plans based on recorded outcomes without bypassing the ACES backend contracts.

## Rationale

After SCN-010, APTL should not grow a second scenario or agent semantics layer. Agent planning remains core to APTL, but it depends on ACES participant/orchestration/evaluation contracts and belongs after the foundational TechVault cutover and backend capability work.

ACTIVE 2026-10-09: PR #855, PR #861 and PR #865 (#554, #557) delivered this work. Installed Claude Code and Codex participants run under RAES action authority (`src/aptl/backends/raes_participant_*.py`). Participant control continues in #1216 and #1224. The issue closed as completed on 2026-10-05. See GitHub issue #419.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#419` (AGT-001: Agent Orchestration / ReAct Planning Layer)
