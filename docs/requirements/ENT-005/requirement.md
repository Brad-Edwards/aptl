---
id: ENT-005
title: "Rocky Linux Victim Server"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 3
created_at: 2026-03-20T06:11:15.338215Z
updated_at: 2026-03-20T06:18:11.649374Z
---

# ENT-005 — Rocky Linux Victim Server

## Statement

The system shall provide a Rocky Linux victim server on the internal network (172.20.2.20) with SSH access, Wazuh agent, a labadmin user with sudo NOPASSWD, and CTF flags at /home/labadmin/user.txt and /root/root.txt.

## Rationale

The victim server is the primary lateral movement target.
