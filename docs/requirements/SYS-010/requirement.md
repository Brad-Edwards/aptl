---
id: SYS-010
title: "Notebook-Style Web User Interface"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 5
created_at: 2026-03-20T06:05:45.592919Z
updated_at: 2026-03-21T06:50:33.807675Z
---

# SYS-010: Notebook-Style Web User Interface

## Statement

The system shall provide an interactive workbench web UI (SvelteKit frontend + FastAPI backend) that unifies scenario execution, terminal access, and container management in a scrollable document-style interface, visually distinct from enterprise SOC dashboards. SIEM integration is limited to automated objective validation (checking whether expected alerts fired for a scenario step), not open-ended query building.

## Rationale

The CLI has limitations for multi-step scenario execution and data visualization. A web UI provides a unified experience while sharing the core domain logic via the FastAPI backend importing src/aptl/core/. Open-ended SIEM exploration is deferred to Wazuh Dashboard; the APTL UI adds value only where it provides scenario-specific context that Wazuh cannot.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/api/main.py` (FastAPI application factory)
- IMPLEMENTS → CODE_FILE `web/src/routes/+page.svelte` (SvelteKit Lab Home page)
- TESTS → TEST `tests/test_api_lab.py` (Lab API endpoint tests)
- TESTS → TEST `tests/test_api_scenarios.py` (Scenario API endpoint tests)
- DOCUMENTS → ADR `docs/adrs/adr-011-web-ui.md` (ADR-011: Notebook-Style Web UI)
- IMPLEMENTS → GITHUB_ISSUE `#219` (SYS-010: Notebook-style web UI (Phase 1 MVP))
- IMPLEMENTS → CODE_FILE `src/aptl/api/routers/scenarios.py` (Scenario catalog summary API router)
