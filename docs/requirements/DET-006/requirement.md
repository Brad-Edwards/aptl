---
id: DET-006
title: "Portable Detection Rule Formats"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:49:59.117046Z
updated_at: 2026-05-03T03:24:20.586939Z
---

# DET-006 — Portable Detection Rule Formats

## Statement

Detection rules shall be expressible in portable, vendor-neutral formats — at minimum Sigma for log-based detections, YARA for file/memory indicators, and Snort/Suricata-compatible format for network signatures — enabling rule sharing and cross-platform use.

## Rationale

Platform-specific Wazuh XML rules are not portable. Sigma's 3,000+ community rules, YARA's standard for malware detection, and Snort-compatible rules are industry standards that enable interoperability.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-022-misp-driven-suricata-rules.md` (ADR-022: MISP-driven Suricata rules)
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/translator.py` (Snort/Suricata-compatible portable rule generator)
- TESTS → TEST `tests/test_misp_suricata_sync.py` (Translator tests (per-IOC type rule shape, ADR-019 alert-only invariant))
- IMPLEMENTS → GITHUB_ISSUE `250` (Issue #250: MISP-to-Suricata IOC sync)
