---
id: INT-002
title: "Atomic Red Team Import"
status: DRAFT
type: INTERFACE
priority: WONT
wave: 2
created_at: 2026-03-21T07:51:53.417167Z
updated_at: 2026-10-05T07:51:12.874346Z
---

# INT-002: Atomic Red Team Import

## Statement

The platform shall import Atomic Red Team YAML test definitions and convert them to APTL AttackStep format, making the library of 1,225 tests across 261 techniques immediately available as scenario building blocks.

## Rationale

WITHDRAWN 2026-10-05: Conversion of Atomic Red Team content is a pack-authoring concern. A released pack runs through the normal pack path. See GitHub issue #445. --- Original rationale: ART is the largest open-source library of executable ATT&CK tests. Importing it immediately addresses the technique coverage gap (SCE-001) without manual scenario authoring for each technique.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#445` (INT-002: Atomic Red Team Import)
