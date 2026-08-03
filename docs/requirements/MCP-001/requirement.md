---
id: MCP-001
title: "Shared MCP Server Library"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:11:51.226199Z
updated_at: 2026-03-20T06:18:11.649566Z
---

# MCP-001 — Shared MCP Server Library

## Statement

The system shall provide a shared TypeScript library (aptl-mcp-common) that all MCP servers depend on, providing: PersistentSession for SSH, SSHConnectionManager for connection pooling, HTTPClient for API access, createMCPServer factory, startServer entry point, typed argument interfaces, and shell formatters.

## Rationale

Without a common library, each MCP server duplicated SSH handling producing copy-paste bugs.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-003-mcp-common-library.md` (ADR-003: MCP Common Library)
- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/server.ts` (MCP server factory)
