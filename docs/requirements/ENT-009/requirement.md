---
id: ENT-009
title: "Intentional Security Misconfigurations"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 3
created_at: 2026-03-20T06:11:27.492322Z
updated_at: 2026-03-20T06:18:11.649459Z
---

# ENT-009: Intentional Security Misconfigurations

## Statement

The enterprise environment shall include deliberate security gaps modeled on OWASP Top 10 patterns: no WAF (A03), no database network ACLs (A05), guest SMB access (A05), no MFA (A07), weak passwords (A07), limited automated response (A09), over-privileged service accounts (A01), and credential sprawl (A05).

## Rationale

A security training lab must have realistic, intentional vulnerabilities.
