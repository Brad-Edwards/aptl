---
id: RTE-001
title: "Scenario Runtime Engine"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-26T05:17:40.154263Z
updated_at: 2026-03-27T04:20:57.390224Z
---

# RTE-001 — Scenario Runtime Engine

## Statement

The platform shall provide a scenario runtime engine that takes a scenario specification (DSL-001) and autonomously drives it through steps with scheduling, pacing, event handling, and state management — replacing the current imperative Python lifecycle code. The engine shall evaluate objectives in real time by executing their validation logic (Wazuh alert queries, command output checks, file existence checks) against live data as the scenario progresses, updating objective completion state and scores incrementally.

## Rationale

The engine is what transforms APTL from a lab you operate manually into a platform that runs autonomously. CALDERA's operation engine, AttackIQ's Anatomic Engine, and CybORG's Gym interface demonstrate that execution engines are the core of every serious simulation platform. The current implementation defines objective validation types (WAZUH_ALERT, COMMAND_OUTPUT, FILE_EXISTS) in Pydantic models and records completion in session state, but nothing actually executes the validation checks — objectives are only marked complete manually. Real-time objective evaluation is essential for autonomous agent runs where no human is watching, and for incremental scoring (OBS-005).

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `237` (RTE-001: Scenario Runtime Engine)
- IMPLEMENTS → GITHUB_ISSUE `252` (Issue #252 — orchestrator-side purple-team continuity carve-out)
- IMPLEMENTS → CODE_FILE `src/aptl/core/continuity.py` (Orchestration-domain post-iteration audit: parser, classifier, audit_target, revert_finding, audit_and_revert)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/continuity.py` (aptl lab continuity-audit command + helpers (issue #252 manual invocation surface))
- IMPLEMENTS → CODE_FILE `src/aptl/cli/lab.py` (Registers continuity-audit under aptl lab)
- IMPLEMENTS → DOCUMENTATION `docs/sdl/runtime-architecture.md` (RTE-001 guardrails section — codex preflight assigning the carve-out to the orchestration domain)
- IMPLEMENTS → ADR `docs/adrs/adr-024-orchestrator-side-purple-continuity-carve-out.md` (ADR-024 — orchestrator-side carve-out design (out-of-band complement to ADR-021))
- TESTS → TEST `tests/test_continuity.py` (Continuity unit + LIVE_LAB integration tests (60 tests; parser/classifier/audit/revert/orchestration/drift guards))
