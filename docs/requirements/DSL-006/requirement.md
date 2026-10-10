---
id: DSL-006
title: "CACAO and Attack Flow Alignment"
status: DEPRECATED
type: INTERFACE
priority: WONT
wave: 3
created_at: 2026-03-21T07:52:39.348426Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# DSL-006: CACAO and Attack Flow Alignment

## Statement

The scenario DSL shall align with industry standards: OASIS CACAO v2.0 concepts for workflow/playbook structure and MITRE Attack Flow v3 concepts for attack graph representation, enabling interoperability with tools that consume these formats.

## Rationale

WITHDRAWN 2026-10-05: The upstream contract (rae#660) closed as not planned. A translation to SDL gives ordinary SDL, so the backend has no work. See GitHub issue #471. --- Original rationale: Proprietary formats create ecosystem lock-in. CACAO v2.0 is the ratified OASIS standard for security playbooks. Attack Flow v3 is the STIX 2.1 extension for attack chain modeling. Alignment enables import/export and cross-tool interoperability.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#471` (DSL-006: CACAO and Attack Flow Alignment)
