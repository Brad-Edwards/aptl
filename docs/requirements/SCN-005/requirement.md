---
id: SCN-005
title: "Lab State Range Snapshots"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:30.377377Z
updated_at: 2026-03-20T06:18:11.649782Z
---

# SCN-005: Lab State Range Snapshots

## Statement

The system shall capture a complete range snapshot with each run, including: software versions, container state, Wazuh rules inventory, network topology, and configuration file hashes.

## Rationale

Comparing runs requires knowing the exact lab state during each run.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-009-scenario-engine.md` (ADR-009: Scenario Engine)
- IMPLEMENTS → CODE_FILE `src/aptl/core/snapshot.py` (Range snapshot capture)
- TESTS → TEST `tests/test_redaction.py` (Tests for shared redaction helper)
- IMPLEMENTS → CODE_FILE `src/aptl/utils/redaction.py` (Shared redaction helper for snapshot/telemetry serialization)
- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/redaction.ts` (Shared redaction helper for MCP serialization (TypeScript twin of the Python helper))
- IMPLEMENTS → ADR `docs/adrs/adr-029-control-plane-secret-handling.md` (ADR-029: Control-Plane Secret Handling in Run Data and Local State)
- TESTS → TEST `mcp/aptl-mcp-common/tests/redaction.test.ts` (Vitest coverage for the TypeScript redaction helper)
- IMPLEMENTS → CODE_FILE `src/aptl/core/endpoints.py` (Snapshot endpoint registry (service + SSH endpoint derivation))
- TESTS → TEST `tests/test_endpoints.py` (Endpoint registry + parse_host_port unit tests)
