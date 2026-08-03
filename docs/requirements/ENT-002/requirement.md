---
id: ENT-002
title: "Samba Active Directory Domain Controller"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 3
created_at: 2026-03-20T06:11:05.880770Z
updated_at: 2026-03-20T06:18:11.649310Z
---

# ENT-002 — Samba Active Directory Domain Controller

## Statement

The system shall provide a Samba AD domain controller (TECHVAULT.LOCAL) on the internal network (172.20.2.10) with 15+ user accounts including service accounts with SPNs (svc-sql, svc-backup), over-privileged accounts (svc-backup as Domain Admin), weak passwords, and anonymous LDAP bind enabled.

## Rationale

Active Directory provides the Path B attack surface.
