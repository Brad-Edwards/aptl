---
id: ENT-008
title: "Docker-Mailserver Email Service"
status: ACTIVE
type: FUNCTIONAL
priority: COULD
wave: 3
created_at: 2026-03-20T06:11:22.991248Z
updated_at: 2026-03-20T06:18:11.649437Z
---

# ENT-008: Docker-Mailserver Email Service

## Statement

The system shall provide an email server (docker-mailserver) on the DMZ (172.20.1.21) supporting SMTP (25), IMAP (143), and submission (587) protocols for the techvault.local domain.

## Rationale

Email is a standard enterprise service providing an additional attack surface.
