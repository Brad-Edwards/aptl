---
id: DET-003
title: "Live SIEM Query Execution from Web UI"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 1
created_at: 2026-03-21T07:49:47.972448Z
updated_at: 2026-10-05T07:51:12.874346Z
---

# DET-003: Live SIEM Query Execution from Web UI

## Statement

The web UI SiemQueryBlock shall execute OpenSearch/Wazuh Indexer queries in real time and display results inline. The currently disabled "Run Query" button shall be connected to the backend query infrastructure that already exists in collectors.py.

## Rationale

WITHDRAWN 2026-10-05: The SDL controls what runs in a lab. A fixed SIEM query page in the backend UI does not fit that model. See GitHub issue #421. --- Original rationale: The query infrastructure exists in the backend (collectors.py) and the UI component exists (SiemQueryBlock.svelte) but the button is disabled. This is a P0 gap because it completes an already-90%-built feature.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#421` (DET-003: Live SIEM Query Execution from Web UI)
