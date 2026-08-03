---
id: SIEM-006
title: "Automated SSH Brute Force Blocking"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-20T06:10:33.649641Z
updated_at: 2026-03-20T06:18:11.649124Z
---

# SIEM-006 — Automated SSH Brute Force Blocking

## Statement

The system shall configure Wazuh active response to block source IPs via firewall-drop for 10 minutes when rule 5763 (6+ SSH authentication failures) fires on agent hosts (victim, workstation).

## Rationale

Active response demonstrates automated blocking as the sole automated defensive action.

## Traceability

- DOCUMENTS → ADR `docs/adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md` (ADR-019 — designates Wazuh AR (firewall-drop) as the lab's prevention layer)
- DOCUMENTS → ADR `docs/adrs/adr-020-wazuh-agents-in-process-vs-sidecar.md` (ADR-020 — in-process agents are the AR enforcement precondition)
- IMPLEMENTS → CONFIG `config/wazuh_cluster/wazuh_manager.conf` (Wazuh manager — &lt;active-response&gt; firewall-drop on rule 5763)
- TESTS → TEST `scripts/test-wazuh-ar-drop.sh` (End-to-end manual AR drop validation (kali → webapp → firewall-drop))
- IMPLEMENTS → GITHUB_ISSUE `249` (Issue #249: Wazuh AR wiring with kali whitelist carve-out)
- IMPLEMENTS → CODE_FILE `containers/_wazuh-agent/aptl-firewall-drop.sh` (Standalone iptables AR script with kali-whitelist carve-out)
- IMPLEMENTS → CONFIG `config/wazuh_cluster/etc/lists/active-response-whitelist` (Kali source-IP whitelist consulted by aptl-firewall-drop on every agent)
- IMPLEMENTS → ADR `docs/adrs/adr-021-active-response-whitelist-via-wrapper.md` (ADR-021: AR whitelist via standalone iptables script)
- DOCUMENTS → DOCUMENTATION `docs/components/wazuh-active-response.md` (Blue-facing reference: AR architecture, wiring, whitelist, severity gate, troubleshooting)
- TESTS → TEST `tests/test_wazuh_active_response.py` (Pytest assertions on AR config + standalone script (10 lab-up + 9 source-level))
- TESTS → TEST `scripts/test-wazuh-ar-whitelist.sh` (Manual E2E for the kali-whitelist carve-out (skip / iptables / delete branches))
- IMPLEMENTS → CODE_FILE `containers/_wazuh-agent/install.sh` (Shared agent installer — extended in #249 to install jq + iptables + the AR wrapper + whitelist on every agent)
- IMPLEMENTS → DOCUMENTATION `docs/components/default-defensive-posture.md` (Default defensive posture: Wazuh active-response posture (all blocks disabled))
- IMPLEMENTS → GITHUB_ISSUE `251` (Issue 251 — document default defensive posture)
- IMPLEMENTS → GITHUB_ISSUE `252` (Issue #252 — out-of-band orchestrator-side complement to SIEM-006's in-band Wazuh AR whitelist (ADR-021))
