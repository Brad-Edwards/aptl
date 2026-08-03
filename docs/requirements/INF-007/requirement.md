---
id: INF-007
title: "Pre-Flight System Requirements Check"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 1
created_at: 2026-03-20T06:09:09.921003Z
updated_at: 2026-03-20T06:18:11.648611Z
---

# INF-007 — Pre-Flight System Requirements Check

## Statement

The system shall validate host system requirements before deployment, including vm.max_map_count >= 262144 (required by OpenSearch/Elasticsearch), available Docker version, and Docker Compose version.

## Rationale

OpenSearch refuses to start when vm.max_map_count is too low, producing a cryptic error. Pre-flight checks fail early with a clear fix instruction.
