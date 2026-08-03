---
id: INT-006
title: "Cortex MCP Server"
status: DRAFT
type: FUNCTIONAL
priority: COULD
wave: 3
created_at: 2026-03-21T07:52:07.965122Z
updated_at: 2026-03-21T07:52:07.965122Z
---

# INT-006 — Cortex MCP Server

## Statement

The platform shall provide an MCP server for Cortex (SOC-004), exposing observable enrichment capabilities (IP, domain, hash, email analysis) to AI agents via standard MCP tool calls.

## Rationale

Cortex is deployed (SOC-004) but has no MCP server, making it the only SOC tool inaccessible to AI agents. Adding an MCP server completes the SOC tool coverage.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#474` (INT-006 — Cortex MCP Server)
