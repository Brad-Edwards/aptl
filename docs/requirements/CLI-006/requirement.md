---
id: CLI-006
title: "CLI/Core Separation for Reuse"
status: ACTIVE
type: CONSTRAINT
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:50.020663Z
updated_at: 2026-03-20T06:18:11.648886Z
---

# CLI-006: CLI/Core Separation for Reuse

## Statement

The CLI shall separate thin CLI layer (src/aptl/cli/) from domain logic (src/aptl/core/). Core modules shall have no dependency on Typer, Rich, or terminal I/O, enabling reuse by the web UI backend and direct scripting.

## Rationale

The future FastAPI web backend needs to import the same logic without CLI framework dependencies.

## Traceability

- CONSTRAINS → ADR `docs/adrs/adr-007-python-cli-control-plane.md` (ADR-007: Python CLI Control Plane)
