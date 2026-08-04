---
id: SYS-006
title: "Python CLI Control Plane"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:05:37.300399Z
updated_at: 2026-03-20T06:18:11.648386Z
---

# SYS-006: Python CLI Control Plane

## Statement

The system shall provide a Python CLI (aptl) as the primary control plane for lab lifecycle management, configuration, scenario execution, and container operations.

## Rationale

The original bash script (start-lab.sh) lacked error handling, state management, configuration validation, and only supported 4 of 9 profiles. A Python CLI provides structured error handling, Pydantic validation, extensibility, and a testable core domain layer shared with the future web UI.
