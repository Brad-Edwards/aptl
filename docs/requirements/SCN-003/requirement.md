---
id: SCN-003
title: "Run Lifecycle Management"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:21.335980Z
updated_at: 2026-03-20T06:18:11.649737Z
---

# SCN-003 — Run Lifecycle Management

## Statement

The scenario engine shall manage run lifecycle: aptl scenario start validates prerequisites, records start timestamp, and creates a run directory; aptl scenario stop records end timestamp, executes data collectors, captures range snapshot, and assembles the run archive.

## Rationale

Precise start/end timestamps define the time window for data collection.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-009-scenario-engine.md` (ADR-009: Scenario Engine)
