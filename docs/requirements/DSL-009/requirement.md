---
id: DSL-009
title: "Simulated User Behavior Profiles in SDL"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-31T02:56:37.902697Z
updated_at: 2026-03-31T02:56:37.902697Z
---

# DSL-009: Simulated User Behavior Profiles in SDL

## Statement

The SDL shall provide a way to declare normal user activity patterns (browsing, email, login schedules, file access, and other baseline traffic) so that scenario authors can specify what realistic background behavior looks like alongside adversarial and defensive activity.

## Rationale

The SDL currently has no first-class mechanism for user simulation. Injects model discrete narrative events, not continuous behavior. Green entities declare organizational identity but carry no behavioral specification. Without declarative user behavior, the full exercise model is incomplete: defenders cannot distinguish attack traffic from normal traffic unless the range generates realistic baselines, and that generation has no specification-layer anchor. CybORG Green agents are the closest precedent. Already noted in docs/sdl/limitations.md as a specification-layer gap. Tracked in GitHub as #242.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#436` (DSL-009: Simulated User Behavior Profiles in SDL)
