---
id: CLI-003
title: "Deterministic 12-Step Startup Sequence"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:40.330915Z
updated_at: 2026-03-20T06:18:11.648822Z
---

# CLI-003 — Deterministic 12-Step Startup Sequence

## Statement

aptl lab start shall execute a deterministic 12-step sequence: (1) load config, (2) load env, (3) check sysreqs, (4) generate SSH keys, (5) generate SSL certs, (6) sync credentials, (7) pre-pull images, (8) docker compose up, (9) wait for indexer health, (10) wait for manager API, (11) test SSH connectivity, (12) capture range snapshot. Each step shall fail the entire sequence on error.

## Rationale

The orchestration order is critical with hard dependencies between steps.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-007-python-cli-control-plane.md` (ADR-007: Python CLI Control Plane)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Lab lifecycle orchestration)
