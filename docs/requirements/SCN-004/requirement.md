---
id: SCN-004
title: "Automated SOC Tool Data Collectors"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:24.962267Z
updated_at: 2026-03-20T06:18:11.649759Z
---

# SCN-004: Automated SOC Tool Data Collectors

## Statement

The system shall automatically collect data from all SOC tools within the run's time window on scenario stop: Wazuh alerts from the Indexer API, Suricata events, TheHive cases, MISP events, and Shuffle workflow executions. Collectors shall be fault-tolerant and use a 120-second HTTP timeout.

## Rationale

Automated collectors ensure complete, consistent data capture for every run.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-009-scenario-engine.md` (ADR-009: Scenario Engine)
- IMPLEMENTS → CODE_FILE `src/aptl/core/collectors.py` (SOC data collectors)
