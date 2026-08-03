---
id: SAF-001
title: "Kill Switch for All Agent and MCP Operations"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-21T07:50:49.548287Z
updated_at: 2026-03-22T01:30:23.591877Z
---

# SAF-001 — Kill Switch for All Agent and MCP Operations

## Statement

The platform shall provide an emergency kill switch (CLI command and UI button) that instantly terminates all MCP server processes and optionally pauses or stops all lab containers, halting all autonomous agent activity.

## Rationale

Required before any autonomous agent operation. RedTeamLLM includes a kill switch as a safety requirement. Without one, a misbehaving agent cannot be stopped short of killing the host process.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `229` (SAF-001: Kill Switch for All Agent and MCP Operations)
- IMPLEMENTS → CODE_FILE `src/aptl/core/kill.py` (Kill switch core logic)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/kill.py` (Kill switch CLI command)
- IMPLEMENTS → CODE_FILE `src/aptl/api/routers/kill.py` (Kill switch API endpoint)
- TESTS → TEST `tests/test_kill.py` (Kill switch core logic tests)
- TESTS → TEST `tests/test_cli_kill.py` (Kill switch CLI tests)
- TESTS → TEST `tests/test_api_kill.py` (Kill switch API endpoint tests)
