---
id: INF-005
title: "Automated SSL Certificate Generation"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:03.791280Z
updated_at: 2026-03-20T06:18:11.648568Z
---

# INF-005 — Automated SSL Certificate Generation

## Statement

The system shall generate TLS certificates for inter-component encryption (Wazuh Manager, Indexer, Dashboard) at first startup, using a dedicated Docker container for certificate generation.

## Rationale

All Wazuh inter-component communication is TLS-encrypted. Manual certificate management would be error-prone and block first-time users.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-001-docker-compose-deployment.md` (ADR-001: Docker Compose Deployment)
