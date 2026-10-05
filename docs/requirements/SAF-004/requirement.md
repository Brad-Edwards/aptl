---
id: SAF-004
title: "MCP Command Filtering (Allowlist/Denylist, Rate Limiting)"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 2
created_at: 2026-03-21T07:51:02.052417Z
updated_at: 2026-10-05T07:51:12.874346Z
---

# SAF-004: MCP Command Filtering (Allowlist/Denylist, Rate Limiting)

## Statement

The MCP layer shall support configurable command filtering: per-server allowlists and denylists for tool invocations, and rate limiting to prevent runaway agent behavior (for example, infinite loop of destructive commands).

## Rationale

WITHDRAWN 2026-10-05: Command filtering of in-range agent actions conflicts with the perimeter containment model (SAF-002, NET-005). #967 covers argument validation. See GitHub issue #456. --- Original rationale: MCP servers currently execute any valid tool call without restriction. Command filtering provides defense-in-depth for autonomous agent operations, complementing the kill switch and tiered autonomy.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#456` (SAF-004: MCP Command Filtering (Allowlist/Denylist, Rate Limiting))
