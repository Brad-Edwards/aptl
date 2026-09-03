---
id: DSL-005
title: "Pre/Post-Conditions and Assertions in Scenarios"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:35.252096Z
updated_at: 2026-03-21T07:52:35.252096Z
---

# DSL-005: Pre/Post-Conditions and Assertions in Scenarios

## Statement

The scenario DSL shall support pre-conditions ("this step requires root access on host X"), post-conditions ("after this step, a reverse shell should be active"), and assertions that can be evaluated during or after execution.

## Rationale

SCN-009 validates only container/profile presence. Semantic pre/post-conditions enable the engine to skip inapplicable steps, verify expected state, and provide meaningful error messages when scenarios fail mid-execution.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#434` (DSL-005: Pre/Post-Conditions and Assertions in Scenarios)
