---
id: DSL-003
title: "Variable System and Runtime Substitution"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:28.159023Z
updated_at: 2026-03-21T07:52:28.159023Z
---

# DSL-003 — Variable System and Runtime Substitution

## Statement

The scenario DSL shall support a variable system with: static parameters (configurable at launch), fact-based substitution (variables resolved from discovered runtime state like IPs, credentials, hostnames), and scoped variable namespaces.

## Rationale

Without variables, every scenario is hardcoded to specific IPs, credentials, and paths. CALDERA's fact store and Atomic Red Team's input_arguments demonstrate that parameterization is standard. Variables enable scenario reuse across different range configurations.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#432` (DSL-003 — Variable System and Runtime Substitution)
