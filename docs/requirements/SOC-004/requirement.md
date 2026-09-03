---
id: SOC-004
title: "Cortex Enrichment Engine"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 2
created_at: 2026-03-20T06:10:46.140823Z
updated_at: 2026-03-20T06:18:11.649219Z
---

# SOC-004: Cortex Enrichment Engine

## Statement

The system shall provide Cortex for automated observable enrichment, analyzing IPs, domains, hashes, and emails against external intelligence sources. Cortex shall be integrated with TheHive for case-driven enrichment.

## Rationale

Cortex automates the enrichment step of the investigation workflow.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-008-soc-stack-integration.md` (ADR-008: SOC Stack Integration)
