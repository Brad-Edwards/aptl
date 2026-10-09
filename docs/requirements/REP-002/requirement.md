---
id: REP-002
title: "Infrastructure-as-Code Abstraction"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:52.367303Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# REP-002: Infrastructure-as-Code Abstraction

## Statement

The platform shall provide a declarative range topology specification separated from Docker Compose deployment details, enabling the same range definition to be deployed to different backends (Docker Compose, container orchestrator, cloud VMs, or hybrid).

## Rationale

INF-010 (DRAFT) addresses container metadata but docker-compose.yml still mixes deployment concerns with environment specification. Separation enables deploying the same logical range to different infrastructure without rewriting definitions.

ACTIVE 2026-10-09: The RAES SDL and the `DeploymentBackend` interface (`src/aptl/core/deployment/`, ADR-013) separate the declared topology from Compose. The issue closed as completed on 2026-10-05 and names no remaining gap. See GitHub issue #451.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#451` (REP-002: Infrastructure-as-Code Abstraction)
