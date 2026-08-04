---
id: NET-005
title: "Zone Isolation via Multi-Homing Only"
status: ACTIVE
type: CONSTRAINT
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:30.552320Z
updated_at: 2026-03-20T06:18:11.648754Z
---

# NET-005: Zone Isolation via Multi-Homing Only

## Statement

Containers on different Docker networks shall be unable to communicate directly. Inter-zone communication shall only be possible through multi-homed containers that bridge network boundaries.

## Rationale

Docker bridge isolation provides zone boundaries without external firewall appliances. A compromised multi-homed container provides a real lateral movement path.

## Traceability

- CONSTRAINS → ADR `docs/adrs/adr-006-four-network-segmentation.md` (ADR-006: Four-Network Segmentation)
