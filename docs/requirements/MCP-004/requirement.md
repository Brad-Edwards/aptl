---
id: MCP-004
title: "SSH MCP Servers for Container Access"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:02.801120Z
updated_at: 2026-03-20T06:18:11.649629Z
---

# MCP-004: SSH MCP Servers for Container Access

## Statement

The system shall provide SSH-based MCP servers for direct container access: mcp-red (Kali), mcp-reverse (reverse engineering). These servers shall expose tools for command execution, session management, and file operations via persistent SSH sessions.

## Rationale

SSH-based servers provide interactive access where AI agents need to execute arbitrary commands.
