---
id: MCP-002
title: "Config-Driven Server Factory"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:11:54.699669Z
updated_at: 2026-03-20T06:18:11.649587Z
---

# MCP-002 — Config-Driven Server Factory

## Statement

Each MCP server shall be defined by a docker-lab-config.json file containing server metadata, connection details, SSH tool definitions, and API tool definitions. The createMCPServer() factory shall generate fully configured servers from this config without server-specific code.

## Rationale

Adding a new container to the MCP layer should require only a config file and a 4-line index.ts.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-003-mcp-common-library.md` (ADR-003: MCP Common Library)
