---
id: SIEM-002
title: "Network-Level Log Forwarding via Syslog"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-20T06:10:20.003858Z
updated_at: 2026-03-20T06:18:11.649036Z
---

# SIEM-002: Network-Level Log Forwarding via Syslog

## Statement

All containers shall forward application logs to Wazuh Manager via rsyslog on port 514/udp. This shall capture web server logs, database queries, authentication events, AD events, and SOC tool outputs.

## Rationale

Syslog captures application-layer events without requiring a Wazuh agent on every container.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-002-wazuh-siem.md` (ADR-002: Wazuh SIEM)
