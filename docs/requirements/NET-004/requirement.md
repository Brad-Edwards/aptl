---
id: NET-004
title: "Internal DNS for Cross-Zone Resolution"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 1
created_at: 2026-03-20T06:09:26.893568Z
updated_at: 2026-03-20T06:18:11.648724Z
---

# NET-004: Internal DNS for Cross-Zone Resolution

## Statement

The system shall provide an internal DNS server (BIND9) that resolves techvault.local hostnames across all network zones, attached to security, DMZ, and internal networks.

## Rationale

Docker bridge networks prevent cross-network hostname resolution by default.
