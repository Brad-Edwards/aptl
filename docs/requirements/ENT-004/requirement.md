---
id: ENT-004
title: "SMB File Server with Open Shares"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 3
created_at: 2026-03-20T06:11:12.614043Z
updated_at: 2026-03-20T06:18:11.649352Z
---

# ENT-004: SMB File Server with Open Shares

## Statement

The system shall provide a Samba file server on the internal network (172.20.2.12) with shares (Public, Shared, Engineering, IT-Backups) allowing anonymous/guest SMB access. Sensitive files including deploy.sh with plaintext credentials shall be accessible on open shares.

## Rationale

The file server provides the Path C entry point for credential harvesting.
