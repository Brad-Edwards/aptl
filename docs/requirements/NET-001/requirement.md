---
id: NET-001
title: "Four Docker Bridge Networks"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:16.688302Z
updated_at: 2026-03-20T06:18:11.648633Z
---

# NET-001: Four Docker Bridge Networks

## Statement

The system shall define four Docker bridge networks: Security (172.20.0.0/24) for SOC tools, DMZ (172.20.1.0/24) for externally reachable services, Internal (172.20.2.0/24) for enterprise services, and Red Team (172.20.4.0/24) for the attack platform.

## Rationale

Four zones model the standard enterprise network architecture that security practitioners need to understand.

## Traceability

- IMPLEMENTS → CONFIG `docker-compose.yml` (Docker Compose network definitions)
- IMPLEMENTS → ADR `docs/adrs/adr-006-four-network-segmentation.md` (ADR-006: Four-Network Segmentation)
