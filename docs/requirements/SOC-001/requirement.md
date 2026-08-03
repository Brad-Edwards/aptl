---
id: SOC-001
title: "Suricata Network IDS"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-20T06:10:37.711456Z
updated_at: 2026-03-20T06:18:11.649144Z
---

# SOC-001 — Suricata Network IDS

## Statement

The system shall deploy Suricata IDS in alert-only mode with pcap capture on DMZ, internal, and security networks. Custom local rules shall cover port scanning, SQL injection in HTTP traffic, command injection, Kerberoasting, SMB enumeration, DNS tunneling, lateral movement SSH, and LDAP enumeration.

## Rationale

Wazuh monitors host-level logs but is blind to network traffic. Suricata fills the critical gap.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-008-soc-stack-integration.md` (ADR-008: SOC Stack Integration)
- IMPLEMENTS → ADR `docs/adrs/adr-022-misp-driven-suricata-rules.md` (ADR-022: MISP-driven Suricata rules)
- IMPLEMENTS → CONFIG `config/suricata/suricata.yaml` (Suricata config (intel-driven rule paths + unix-command socket))
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/translator.py` (IOC → Suricata rule translator)
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/rule_writer.py` (Atomic, idempotent Suricata rule file writer)
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/suricata_reloader.py` (Suricata unix-command socket rule-reload client)
- TESTS → TEST `tests/test_misp_suricata_sync.py` (MISP→Suricata sync service unit tests)
- IMPLEMENTS → GITHUB_ISSUE `250` (Issue #250: MISP-to-Suricata IOC sync)
- IMPLEMENTS → ADR `docs/adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md` (ADR-019: Suricata stays IDS-only; prevention via Wazuh AR)
- IMPLEMENTS → GITHUB_ISSUE `247` (Issue #247: Switch Suricata to inline IPS — closed via ADR-019 (IDS-only retained))
- IMPLEMENTS → DOCUMENTATION `docs/components/default-defensive-posture.md` (Default defensive posture: Suricata IDS section)
- IMPLEMENTS → GITHUB_ISSUE `251` (Issue 251 — document default defensive posture)
