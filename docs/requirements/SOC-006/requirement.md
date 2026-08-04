---
id: SOC-006
title: "End-to-End SOC Workflow Integration"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-20T06:10:53.237748Z
updated_at: 2026-03-20T06:18:11.649268Z
---

# SOC-006: End-to-End SOC Workflow Integration

## Statement

The SOC tools shall be integrated to support the full workflow: Wazuh alerts trigger Shuffle playbooks, which query MISP for threat context and create TheHive cases with enrichment data. Suricata alerts shall be correlated with Wazuh host-based detections.

## Rationale

The value is in the integration of individual tools.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-008-soc-stack-integration.md` (ADR-008: SOC Stack Integration)
- IMPLEMENTS → GITHUB_ISSUE `249` (Issue #249: closes the SOC integration loop (Wazuh detects → manager fires AR → in-process agent enforces))
- IMPLEMENTS → CONFIG `config/wazuh_cluster/wazuh_manager.conf` (Wazuh manager: AR commands and active-response blocks tying detections to dispatched commands (SOC integration loop))
- IMPLEMENTS → DOCUMENTATION `docs/components/default-defensive-posture.md` (Default defensive posture: SOC stack overview (Shuffle, TheHive, Wazuh integration))
- IMPLEMENTS → GITHUB_ISSUE `251` (Issue 251: document default defensive posture)
