---
id: INF-003
title: "Health Checks for All Containers"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:08:57.534805Z
updated_at: 2026-03-20T06:18:11.648524Z
---

# INF-003 — Health Checks for All Containers

## Statement

Every container shall define a Docker health check with appropriate start_period (120-300s for SOC tools), interval, timeout, and retry parameters tuned to observed cold-start times.

## Rationale

Health checks enable dependency-aware startup ordering and allow the CLI orchestrator to determine when services are ready before proceeding.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-005-docker-compose-profiles.md` (ADR-005: Docker Compose Profiles)
