---
id: EXP-011
title: "Apparatus Readiness and Validity Gate"
status: DRAFT
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-07-11T02:30:43.593978Z
updated_at: 2026-07-11T02:30:43.593978Z
---

# EXP-011: Apparatus Readiness and Validity Gate

## Statement

Before a campaign and where configured before each trial, APTL shall run a recorded apparatus gate covering ACES backend conformance, clean-state/isolation, safety controls, required services, collector readiness, clock synchronization, storage headroom, resource budgets, artifact availability and digest verification, and declared measurement-channel health. Thresholds and fail/warn policy shall be strict, versioned AptlConfig settings. Required gate failures shall prevent execution; warnings and waivers shall be explicit evidence in every affected run. The gate shall be extensible through capability-declared checks and shall not execute arbitrary code from experiment inputs.

## Rationale

Cyber-range configuration and measurement health affect validity. A self-test and readiness record make APTL behave like a scientific instrument instead of merely starting containers, while preserving configurable local operation and fail-closed safety.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `Brad-Edwards/aptl#753` (EXP-011: Apparatus readiness and validity gate)
