---
id: UI-001
title: "Interactive Scenario Workbench View"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 5
created_at: 2026-03-20T06:12:43.180827Z
updated_at: 2026-03-21T06:19:18.012426Z
---

# UI-001 — Interactive Scenario Workbench View

## Statement

The web UI shall provide a scrollable scenario workbench interleaving narrative blocks (markdown), terminal blocks (xterm.js), SIEM query blocks (inline OpenSearch queries), container status blocks, and hint toggles with progressive disclosure.

## Rationale

The workbench replaces the multi-window terminal workflow.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-011-web-ui.md` (ADR-011: Web UI)
- IMPLEMENTS → GITHUB_ISSUE `224` (PR #224: Add interactive scenario workbench UI)
- TESTS → TEST `web/tests/lib/markdown.test.ts` (Markdown renderer tests (9 tests))
- IMPLEMENTS → CODE_FILE `web/src/routes/scenarios/[id]/+page.svelte` (Workbench page (scenario route))
- IMPLEMENTS → GITHUB_ISSUE `223` (UI-001: Interactive Scenario Workbench View)
- IMPLEMENTS → CODE_FILE `web/src/lib/components/workbench/` (Workbench block components (9 components))
- IMPLEMENTS → CODE_FILE `web/src/lib/markdown.ts` (Markdown renderer (marked + DOMPurify))
- IMPLEMENTS → CODE_FILE `src/aptl/api/scenario_projection.py` (Workbench block projection (build_workbench_blocks) — moved backend from web buildBlockSequence)
- TESTS → TEST `tests/test_scenario_detail.py` (Workbench block projection tests (replaces web buildBlockSequence tests))
