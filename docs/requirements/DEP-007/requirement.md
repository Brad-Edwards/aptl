---
id: DEP-007
title: "Experiment Resource Budgets and Enforcement"
status: DRAFT
type: NON_FUNCTIONAL
priority: WONT
wave: 3
created_at: 2026-03-21T07:54:04.079705Z
updated_at: 2026-10-05T07:51:12.874346Z
---

# DEP-007: Experiment Resource Budgets and Enforcement

## Statement

APTL shall enforce configurable preflight and runtime budgets for campaign duration, per-trial timeout, concurrency, retries, host resources, archive growth, and standardized participant usage. The scheduler shall stop admitting new trials and, where policy requires, terminate active work through the existing safe control path before a hard limit is exceeded, recording the decision and terminal state. Monetary caps may be enforced only when usage and a pinned price source are available. APTL shall not implement cloud-provider billing estimation or account management.

## Rationale

WITHDRAWN 2026-10-05: This budget scope is larger than the serial runner needs. #459 keeps the typed timeout, cleanup and storage limits. #753 checks resources before a run. Retries and concurrency are not planned. See GitHub issue #469. --- Original rationale: A single-user instrument still needs bounded unattended execution. Generic enforceable resource limits are reliable and provider-neutral; cloud cost prediction is deployment finance and cannot be made scientifically or operationally credible inside APTL.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#469` (DEP-007: Experiment resource budgets and enforcement)
