---
id: NET-003
title: "Multi-Network Container Attachment"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:24.291706Z
updated_at: 2026-03-20T06:18:11.648677Z
---

# NET-003: Multi-Network Container Attachment

## Statement

Containers that bridge network zones shall be attached to multiple Docker networks with a unique IP on each. Multi-homed containers include: Wazuh Manager (security, DMZ, internal), Kali (redteam, DMZ, internal), Suricata (security, DMZ, internal), DNS (security, DMZ, internal), web app (DMZ, internal), and mail server (DMZ, internal).

## Rationale

Multi-homing enables realistic service placement and attacker pivoting simulation.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-006-four-network-segmentation.md` (ADR-006: Four-Network Segmentation)
