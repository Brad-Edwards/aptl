---
id: SIM-005
title: "Pacing Control"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:53:28.736599Z
updated_at: 2026-06-28T17:13:12.331184Z
---

# SIM-005: Pacing Control

## Statement

The simulation engine shall support pacing control: configurable timing between steps (immediate, fixed delay, randomized intervals) and the ability to accelerate or decelerate execution to model realistic adversary dwell times or compress long exercises. ACES scope constraint (ADR-035 / SCN-010): step advancement and pacing are owned by the ACES time-semantics surface: pacing/advancement/synchronization semantics (SEM-228, aces#284), the time-progression DSL surface (DSL-127, aces#287), and the runtime advancement lifecycle (RUN-318, aces#290). This requirement shall expose/configure that ACES time surface, NOT implement a parallel pacing/scheduling engine. Dependency: blocked on the ACES time-semantics contracts (ACES milestone 41), which are open/unbuilt upstream, downstream-dependent, not yet buildable.

## Rationale

Real adversaries operate with dwell times of hours to months. Immediate sequential execution is unrealistic and doesn't test time-based detections. Pacing control enables modeling realistic adversary tempo.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#461` (SIM-005: Pacing Control)
