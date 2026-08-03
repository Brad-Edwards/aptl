---
id: INF-010
title: "Declarative Range Definition"
status: DRAFT
type: FUNCTIONAL
priority: MUST
wave: 6
created_at: 2026-03-21T03:56:18.575009Z
updated_at: 2026-03-21T03:57:22.319321Z
---

# INF-010 — Declarative Range Definition

## Statement

The system shall provide a single declarative range definition that describes the containers in a lab topology — including their names, network addresses, exposed services, SSH access parameters, and roles. All components that need to know about containers (orchestration, terminal access, snapshots, UI, health checks) shall derive their behavior from this definition rather than maintaining independent hardcoded maps.

## Rationale

Container SSH parameters, port mappings, and service endpoints are currently duplicated across terminal.py, snapshot.py, lab.py, and ContainerCard.svelte. Adding a new scenario or container requires updating every copy in lockstep. A single range definition eliminates this duplication and makes the system extensible to arbitrary lab topologies.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#500` (INF-010 — Declarative Range Definition)
