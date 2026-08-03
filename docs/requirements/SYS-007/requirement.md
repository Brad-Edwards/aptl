---
id: SYS-007
title: "Model Context Protocol Server Layer"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:05:39.709305Z
updated_at: 2026-03-20T06:18:11.648412Z
---

# SYS-007 — Model Context Protocol Server Layer

## Statement

The system shall expose all lab components (containers, SIEM, SOC tools) to AI agents via MCP (Model Context Protocol) servers, enabling programmatic attack execution, SIEM investigation, case management, and orchestration through standard MCP tool calls.

## Rationale

The core research purpose of APTL is studying how AI agents perform in attack-and-defense cycles. MCP provides the standard protocol for AI agent tool use, enabling any MCP-compatible agent to control the lab without custom integrations.
