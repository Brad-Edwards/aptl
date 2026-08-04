---
id: INF-001
title: "Docker Compose Declarative Deployment"
status: ACTIVE
type: CONSTRAINT
priority: MUST
wave: 1
created_at: 2026-03-20T06:08:50.601173Z
updated_at: 2026-03-20T06:18:11.648478Z
---

# INF-001: Docker Compose Declarative Deployment

## Statement

All lab components shall be defined as Docker containers in a single docker-compose.yml file, deployable via docker compose up with no external infrastructure requirements.

## Rationale

Docker Compose provides declarative, reproducible deployment with instant startup and zero cloud costs. Replaces the original AWS/Terraform model that required 30-60 minutes and ~$280/month.

## Traceability

- CONSTRAINS → ADR `docs/adrs/adr-001-docker-compose-deployment.md` (ADR-001: Docker Compose Deployment)
- IMPLEMENTS → CONFIG `docker-compose.yml` (Docker Compose service definitions)
