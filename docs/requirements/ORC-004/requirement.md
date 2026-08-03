---
id: ORC-004
title: "Agent-to-Agent Communication and Shared Context"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:51:24.830558Z
updated_at: 2026-06-28T17:13:20.358846Z
---

# ORC-004 — Agent-to-Agent Communication and Shared Context

## Statement

The platform shall provide a mechanism for multiple agents to communicate findings and share context (e.g. red agent shares discovered credentials with a lateral movement specialist, or blue agent alerts red agent's observer about a detection). ACES scope constraint (ADR-035 / SCN-010): inter-participant shared context is owned by the ACES shared-operational-state / derived-context contract (API-410, aces#253) and multi-participant coordination & delegation (ACT-612, aces#214); shared context shall flow through those contracts — NOT a bespoke APTL inter-agent bus that becomes a parallel source of truth. Sub-capability of multi-agent coordination, subordinate to AGT-002. Dependency: blocked on ACES API-410 / ACT-612 (open/unbuilt upstream).

## Rationale

Multi-agent operation (AGT-002) requires inter-agent communication. Without shared context, agents duplicate work and cannot coordinate strategies across specializations.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#450` (ORC-004 — Agent-to-Agent Communication and Shared Context)
