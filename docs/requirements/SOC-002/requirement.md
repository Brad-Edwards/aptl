---
id: SOC-002
title: "MISP Threat Intelligence Platform"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-20T06:10:40.743285Z
updated_at: 2026-03-20T06:18:11.649166Z
---

# SOC-002 — MISP Threat Intelligence Platform

## Statement

The system shall provide a MISP instance pre-loaded with IOCs relevant to lab scenarios, supporting REST API access for MCP-driven queries, indicator submission, ATT&CK technique mapping, and correlation with SIEM alerts.

## Rationale

Without threat intelligence, Wazuh alerts contain raw event data but no context.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-008-soc-stack-integration.md` (ADR-008: SOC Stack Integration)
- IMPLEMENTS → ADR `docs/adrs/adr-022-misp-driven-suricata-rules.md` (ADR-022: MISP-driven Suricata rules)
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/main.py` (MISP→Suricata sync service entrypoint and loop)
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/misp_client.py` (MISP REST client (curl-subprocess, secret-safe headers))
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/config.py` (Sync service env-driven Pydantic config)
- IMPLEMENTS → CONFIG `docker-compose.yml` (Docker Compose - misp-suricata-sync service block)
- TESTS → TEST `tests/test_misp_suricata_sync.py` (MISP→Suricata sync service unit tests)
- IMPLEMENTS → GITHUB_ISSUE `250` (Issue #250: MISP-to-Suricata IOC sync)
- IMPLEMENTS → DOCUMENTATION `docs/components/default-defensive-posture.md` (Default defensive posture: MISP IOCs section)
- IMPLEMENTS → GITHUB_ISSUE `251` (Issue 251 — document default defensive posture)
