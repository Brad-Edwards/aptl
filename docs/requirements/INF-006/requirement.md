---
id: INF-006
title: "Environment-Based Credential Management"
status: ACTIVE
type: CONSTRAINT
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:07.001355Z
updated_at: 2026-03-20T06:18:11.648589Z
---

# INF-006: Environment-Based Credential Management

## Statement

The system shall manage all service credentials via a .env file that is never committed to version control. The CLI shall synchronize credentials to Wazuh configuration files at startup. docker-compose.yml shall reference credentials exclusively through variable substitution.

## Rationale

Prevents credential leakage to version control while enabling reproducible deployments.
