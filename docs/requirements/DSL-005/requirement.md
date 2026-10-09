---
id: DSL-005
title: "Pre/Post-Conditions and Assertions in Scenarios"
status: DEPRECATED
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:35.252096Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# DSL-005: Pre/Post-Conditions and Assertions in Scenarios

## Statement

The scenario DSL shall support pre-conditions ("this step requires root access on host X"), post-conditions ("after this step, a reverse shell should be active"), and assertions that can be evaluated during or after execution.

## Rationale

DEPRECATED 2026-10-09: ADR-035 deprecates DSL-002 to DSL-009. #434 delivered the LilRAE side: the manifest declares propositions and assertions, and `_raes_proposition_truth.py` projects truth from real evidence (#911, #1020). The issue closed as completed on 2026-10-05. See GitHub issue #434. --- Original rationale: SCN-009 validates only container/profile presence. Semantic pre/post-conditions enable the engine to skip inapplicable steps, verify expected state, and provide meaningful error messages when scenarios fail mid-execution.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#434` (DSL-005: Pre/Post-Conditions and Assertions in Scenarios)
