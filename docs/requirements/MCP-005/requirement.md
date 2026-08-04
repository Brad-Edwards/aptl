---
id: MCP-005
title: "REST API MCP Servers for SOC Tools"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:06.806135Z
updated_at: 2026-03-20T06:18:11.649650Z
---

# MCP-005: REST API MCP Servers for SOC Tools

## Statement

The system shall provide API-based MCP servers for SOC tool integration: mcp-wazuh (SIEM API), mcp-indexer (OpenSearch DSL queries), mcp-network (Suricata via indexer), mcp-threatintel (MISP), mcp-casemgmt (TheHive), mcp-soar (Shuffle). Each shall use the common library's HTTPClient.

## Rationale

SOC tools expose REST APIs that AI agents access for investigation, enrichment, and response.
