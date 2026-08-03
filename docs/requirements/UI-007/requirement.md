---
id: UI-007
title: "Web GUI Design Specification"
status: ACTIVE
type: NON_FUNCTIONAL
priority: COULD
wave: 5
created_at: 2026-06-23T04:29:41.235038Z
updated_at: 2026-06-23T04:30:19.228370Z
---

# UI-007 — Web GUI Design Specification

## Statement

The APTL web GUI shall conform to a documented design specification covering information architecture, route map, per-page interaction design (distinguishing human-investigation surfaces from read-only status), authentication/security UX, and alignment with the existing Svelte component and design system. The design shall be derived from the approved web GUI product scope (UI-006) and serve as the build specification for the implementation (UI-008).

## Rationale

A web GUI built without an explicit design specification accretes ad-hoc pages (the current MVP) rather than a coherent surface. Separating design from implementation lets the design be reviewed against the scope before code is written, and gives the implementation a concrete target.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `540` (UI-007 — Design the APTL web GUI)
- IMPLEMENTS → DOCUMENTATION `docs/specs/web-gui-design.md` (APTL Web GUI Design Specification)
- IMPLEMENTS → DOCUMENTATION `docs/specs/web-gui-design-preflight.md` (Web GUI Design Preflight Guardrails)
