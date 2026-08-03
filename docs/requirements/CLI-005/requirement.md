---
id: CLI-005
title: "Scenario Start/Stop/List Commands"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:44.776757Z
updated_at: 2026-03-20T06:18:11.648865Z
---

# CLI-005 — Scenario Start/Stop/List Commands

## Statement

The CLI shall provide aptl scenario start, aptl scenario stop, and aptl scenario list commands for scenario lifecycle management.

## Rationale

Scenario execution is the primary research workflow.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/cli/scenario.py` (aptl scenario list/start/stop CLI through ACES backend)
- TESTS → TEST `tests/test_cli_scenario.py` (aptl scenario list/start/stop CLI tests)
