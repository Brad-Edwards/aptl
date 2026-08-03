---
id: DEP-006
title: "Isolation Tier Selection"
status: DRAFT
type: NON_FUNCTIONAL
priority: WONT
wave: 4
created_at: 2026-03-21T07:54:00.192209Z
updated_at: 2026-03-21T07:54:00.192209Z
---

# DEP-006 — Isolation Tier Selection

## Statement

The platform shall support selecting isolation tiers per-component: standard container (runc), hardened container (gVisor), microVM (Kata/Firecracker), or full VM — based on the security requirements and performance needs of each component.

## Rationale

Container escape is a real risk (CVE-2021-30465 etc.). gVisor provides best isolation but 216x slower I/O. Kata Containers adds VM isolation but still vulnerable to some attacks (USENIX Security '23). The right isolation tier depends on the component's threat model.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#491` (DEP-006 — Isolation Tier Selection)
