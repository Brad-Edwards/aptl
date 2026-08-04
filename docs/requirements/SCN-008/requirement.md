---
id: SCN-008
title: "Append-Only Event Timeline"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 4
created_at: 2026-03-20T06:12:37.730012Z
updated_at: 2026-03-20T06:18:11.649847Z
---

# SCN-008: Append-Only Event Timeline

## Statement

The system shall maintain an append-only JSONL event log during scenario execution, recording: scenario start/stop, precondition application, objective completion/failure, alert matches, hint requests, and evaluation events. Events shall be flushed immediately for crash safety.

## Rationale

The event timeline provides a chronological record for post-hoc analysis.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/core/events.py` (Event timeline logger)
