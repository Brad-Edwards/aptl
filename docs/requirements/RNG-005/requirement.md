---
id: RNG-005
title: "C2 Framework Integration"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 2
created_at: 2026-03-21T07:50:24.528016Z
updated_at: 2026-10-05T07:51:12.874346Z
---

# RNG-005: C2 Framework Integration

## Statement

The lab shall include a command-and-control framework (for example, Mythic, Sliver, or equivalent) with an associated MCP server, enabling realistic adversary simulation with implant deployment, beacon management, and post-exploitation workflows.

## Rationale

WITHDRAWN 2026-10-05: A C2 server that a pack declares is an ordinary node. No pack needs a separate C2 capability. See GitHub issue #454. --- Original rationale: Real adversaries use C2 frameworks. Without C2, red team exercises are limited to manual command execution. Mythic and Sliver are open-source, well-documented, and widely used in professional red team operations.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#454` (RNG-005: C2 Framework Integration)
