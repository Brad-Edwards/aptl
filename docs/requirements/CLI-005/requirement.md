---
id: CLI-005
title: "Scenario Start/Stop/List Commands"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:44.776757Z
updated_at: 2026-10-09T12:05:03.000000Z
---

# CLI-005: Scenario Start/Stop/List Commands

## Statement

The CLI shall provide aptl scenario start, aptl scenario stop, and aptl scenario list commands for scenario lifecycle management.

## Rationale

UPDATED 2026-10-09: ba1e5491 removed the aptl scenario start, stop and list commands named above on 2026-03-29, with src/aptl/cli/scenario.py and tests/test_cli_scenario.py. aptl lab scenarios, aptl lab start --scenario and aptl lab stop now provide that lifecycle, and the traces point at them. The statement is left as written for Ground Control. See GitHub issue #954. --- Original rationale: Scenario execution is the primary research workflow.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/cli/lab.py` (aptl lab scenarios, aptl lab start --scenario and aptl lab stop)
- TESTS → TEST `tests/test_cli.py` (TestLabStartCommand, TestLabStopCommand and the aptl lab scenarios tests)
