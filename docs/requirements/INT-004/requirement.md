---
id: INT-004
title: "STIX/TAXII Threat Intelligence Consumption"
status: DRAFT
type: INTERFACE
priority: WONT
wave: 4
created_at: 2026-03-21T07:52:00.878032Z
updated_at: 2026-03-21T07:52:00.878032Z
---

# INT-004 — STIX/TAXII Threat Intelligence Consumption

## Statement

The platform shall consume structured threat intelligence via STIX 2.1 bundles and TAXII feeds, using threat data to inform scenario generation, detection rule creation, and ATT&CK coverage analysis.

## Rationale

MISP is deployed but STIX/TAXII integration enables consuming from any CTI source (MITRE ATT&CK STIX data, ISACs, commercial feeds). This connects APTL to the broader threat intelligence ecosystem.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#494` (INT-004 — STIX/TAXII Threat Intelligence Consumption)
