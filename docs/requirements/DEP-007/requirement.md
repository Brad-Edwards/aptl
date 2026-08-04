---
id: DEP-007
title: "Experiment Resource Budgets and Enforcement"
status: DRAFT
type: NON_FUNCTIONAL
priority: SHOULD
wave: 3
created_at: 2026-03-21T07:54:04.079705Z
updated_at: 2026-07-11T02:30:30.167645Z
---

# DEP-007: Experiment Resource Budgets and Enforcement

## Statement

APTL shall enforce configurable preflight and runtime budgets for campaign duration, per-trial timeout, concurrency, retries, host resources, archive growth, and standardized participant usage. The scheduler shall stop admitting new trials and, where policy requires, terminate active work through the existing safe control path before a hard limit is exceeded, recording the decision and terminal state. Monetary caps may be enforced only when usage and a pinned price source are available. APTL shall not implement cloud-provider billing estimation or account management.

## Rationale

A single-user instrument still needs bounded unattended execution. Generic enforceable resource limits are reliable and provider-neutral; cloud cost prediction is deployment finance and cannot be made scientifically or operationally credible inside APTL.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#469` (DEP-007: Experiment resource budgets and enforcement)
