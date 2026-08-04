---
id: AGT-001
title: "ACES-Aligned Agent Orchestration Layer"
status: DRAFT
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-21T07:48:56.306563Z
updated_at: 2026-06-22T01:20:43.180956Z
---

# AGT-001: ACES-Aligned Agent Orchestration Layer

## Statement

The platform shall provide an agent orchestration layer that consumes ACES scenario, runtime, participant, orchestration, and evaluation surfaces, instantiates configured LLM-backed or scripted agents, invokes APTL/MCP tools under declared authority and scope, observes portable workflow/evaluation state, and adapts plans based on recorded outcomes without bypassing the ACES backend contracts.

## Rationale

After SCN-010, APTL should not grow a second scenario or agent semantics layer. Agent planning remains core to APTL, but it depends on ACES participant/orchestration/evaluation contracts and belongs after the foundational TechVault cutover and backend capability work.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#419` (AGT-001: Agent Orchestration / ReAct Planning Layer)
