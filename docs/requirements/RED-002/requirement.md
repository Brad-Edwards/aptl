---
id: RED-002
title: "Kali Multi-Network Access"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 3
created_at: 2026-03-20T06:11:34.461380Z
updated_at: 2026-03-20T06:18:11.649503Z
---

# RED-002 — Kali Multi-Network Access

## Statement

Kali shall be attached to three networks: redteam (172.20.4.30), DMZ (172.20.1.30), and internal (172.20.2.35). Extra_hosts entries shall map techvault.local domain names to internal IPs for Kerberos and service discovery.

## Rationale

Kali needs DMZ and internal access for the full attack chain.
