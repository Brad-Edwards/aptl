---
id: UI-008
title: "Web GUI Implementation as a Shipped Surface"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 5
created_at: 2026-06-23T04:29:46.901590Z
updated_at: 2026-06-23T04:30:19.228396Z
---

# UI-008 — Web GUI Implementation as a Shipped Surface

## Statement

The platform shall provide a web GUI that implements the approved design specification (UI-007), is served by `aptl web serve` (the built assets mounted by the FastAPI application rather than dev-served), exposes authenticated API endpoints under `src/aptl/api/` with a CSRF/origin-safe proxy, and ships with vitest coverage in `web/tests/` and pytest coverage in `tests/`. DET-003 (Live SIEM Query Execution) shall be delivered as a line item of this implementation.

## Rationale

The MVP frontend is not bundled into `aptl web serve` and carried security findings (#415 unauthenticated docker.sock-mounting API, #521 token-injecting proxy without CSRF gate). A shipped surface must resolve those and be reachable out of the box. Consolidating DET-003 here avoids finishing an isolated button on a surface whose shape is still undecided.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `541` (UI-008 — Implement the APTL web GUI)
