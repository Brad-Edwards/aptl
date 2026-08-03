---
id: SIM-003
title: "Abstract Simulation Model"
status: DRAFT
type: FUNCTIONAL
priority: COULD
wave: 3
created_at: 2026-03-21T07:53:21.665922Z
updated_at: 2026-03-21T07:53:21.665922Z
---

# SIM-003 — Abstract Simulation Model

## Statement

The platform shall provide an abstract simulation model of the range (network topology, host state, vulnerability surface) that enables what-if analysis, faster-than-real-time execution, and RL agent training without requiring full container emulation.

## Rationale

Full emulation is slow (CyGIL training took days for small networks). CyberBattleSim and YAWNING-TITAN demonstrate that abstract simulation enables rapid experimentation. An abstract model complements the emulated range for different use cases.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#486` (SIM-003 — Abstract Simulation Model)
