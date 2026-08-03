---
id: INF-004
title: "Memory Limits for All Containers"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:01.207689Z
updated_at: 2026-03-20T06:18:11.648546Z
---

# INF-004 — Memory Limits for All Containers

## Statement

Every container shall declare a memory limit (deploy.resources.limits.memory) to prevent resource starvation. Limits range from 128MB (DNS, Redis) to 2GB (Wazuh Indexer) based on observed usage.

## Rationale

Without memory limits, a single container can consume all available host memory, causing OOM kills across the entire lab.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-005-docker-compose-profiles.md` (ADR-005: Docker Compose Profiles)
