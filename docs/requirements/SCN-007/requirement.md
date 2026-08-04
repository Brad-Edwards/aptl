---
id: SCN-007
title: "Objective-Based Scoring with Hints"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 4
created_at: 2026-03-20T06:12:34.196096Z
updated_at: 2026-03-20T06:18:11.649825Z
---

# SCN-007: Objective-Based Scoring with Hints

## Statement

Scenarios shall define red and blue objectives with point values. Red objectives shall be scored via Wazuh alert matching or command output verification. Hints shall provide progressive disclosure with point penalties.

## Rationale

Objective scoring provides a quantitative measure of agent/operator performance.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/core/flags.py` (Objective scoring engine)
