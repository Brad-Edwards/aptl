---
id: REP-005
title: "Environment Seeding (Pre-Planted Artifacts)"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 3
created_at: 2026-03-21T07:53:05.021257Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# REP-005: Environment Seeding (Pre-Planted Artifacts)

## Statement

The platform shall support declarative specification of pre-planted artifacts: credentials, vulnerable configurations, user accounts, file system state, and other environmental preconditions required by a scenario, applied automatically at run start.

## Rationale

ENT-009 describes static misconfigurations baked into containers. Declarative seeding enables different scenarios to plant different artifacts without rebuilding containers, and captures the full experiment precondition for reproducibility.

ACTIVE 2026-10-09: The account, content, dataset and seed realization paths exist (`raes_account_realization.py`, `raes_content_realization.py`, `_compose_seed_execution.py`; ADR-043). The issue closed as completed on 2026-10-05 and names no missing content type. See GitHub issue #479.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#479` (REP-005: Environment Seeding (Pre-Planted Artifacts))
