---
id: SCN-006
title: "Run Archive Packaging and S3 Export"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 4
created_at: 2026-03-20T06:12:31.195451Z
updated_at: 2026-03-20T06:18:11.649805Z
---

# SCN-006: Run Archive Packaging and S3 Export

## Statement

The system shall support exporting completed runs as tar.gz archives with SHA-256 checksums, with optional S3 upload. Run storage backend shall be configurable via aptl.json.

## Rationale

Run archives enable sharing, long-term storage, and offline analysis.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/core/exporter.py` (Run archive exporter)
- IMPLEMENTS → ADR `docs/adrs/adr-009-scenario-engine.md` (ADR-009: Scenario Engine)
