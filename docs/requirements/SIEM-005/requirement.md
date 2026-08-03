---
id: SIEM-005
title: "Custom Detection Rules and Decoders"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-20T06:10:29.907684Z
updated_at: 2026-03-20T06:18:11.649102Z
---

# SIEM-005 — Custom Detection Rules and Decoders

## Statement

The system shall include custom Wazuh detection rules and decoders for all scenario attack patterns: web application attacks (SQLi, XSS, command injection, information disclosure), AD attacks (brute force, Kerberoasting, LDAP enumeration, service account abuse), database attacks (unexpected connections, large exports), and Suricata correlation rules.

## Rationale

Default Wazuh rules do not detect application-specific attacks in the TechVault environment.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-002-wazuh-siem.md` (ADR-002: Wazuh SIEM)
- IMPLEMENTS → DOCUMENTATION `docs/components/default-defensive-posture.md` (Default defensive posture: Wazuh detection rules section)
- IMPLEMENTS → GITHUB_ISSUE `251` (Issue 251 — document default defensive posture)
