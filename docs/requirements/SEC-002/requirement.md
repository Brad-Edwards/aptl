---
id: SEC-002
title: "Python Test Suite (587+ Tests)"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:10:06.719135Z
updated_at: 2026-03-20T06:18:11.648929Z
---

# SEC-002: Python Test Suite (587+ Tests)

## Statement

The Python CLI and core modules shall maintain a test suite covering all core modules (lab, config, env, ssh, certs, credentials, services, scenarios, session, events, collectors, runstore, exporter, snapshot, health, flags, detection). Tests shall use mocking for Docker and subprocess calls.

## Rationale

587+ tests provide confidence in orchestration logic, credential handling, and data collection.
