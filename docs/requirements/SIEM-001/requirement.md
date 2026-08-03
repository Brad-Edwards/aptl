---
id: SIEM-001
title: "Host-Level Monitoring via Wazuh Agents"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-20T06:10:16.877657Z
updated_at: 2026-03-20T06:18:11.649016Z
---

# SIEM-001 — Host-Level Monitoring via Wazuh Agents

## Statement

The system shall deploy Wazuh agents on SSH-enabled containers (victim, workstation, reverse, kali) to provide host-level visibility including file integrity monitoring, rootkit detection, system call auditing, and process monitoring via port 1514/tcp.

## Rationale

Agent-based monitoring provides host-level telemetry that syslog cannot.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-002-wazuh-siem.md` (ADR-002: Wazuh SIEM)
- IMPLEMENTS → GITHUB_ISSUE `248` (Issue #248: in-process Wazuh agents on webapp/fileshare/ad/dns (replaces sidecar pattern))
- IMPLEMENTS → ADR `docs/adrs/adr-020-wazuh-agents-in-process-vs-sidecar.md` (ADR-020: Wazuh agents run in-process on the target containers)
- IMPLEMENTS → CODE_FILE `containers/_wazuh-agent/install.sh` (Shared Wazuh agent apt-install helper (sidecar + in-process targets))
- IMPLEMENTS → CODE_FILE `containers/_wazuh-agent/wazuh-agent.sh` (Shared Wazuh agent runtime bootstrap (registers, starts daemon, supervises))
- IMPLEMENTS → CODE_FILE `containers/_wazuh-agent/ossec.conf.template` (Shared Wazuh agent ossec.conf template)
- IMPLEMENTS → CONFIG `config/wazuh_cluster/wazuh_manager.conf` (Wazuh manager — &lt;auth&gt;&lt;force&gt; allows in-process takeover from sidecar)
- TESTS → TEST `tests/test_in_process_agents.py` (Integration tests for in-process Wazuh agent placement, NET_ADMIN, daemons, log paths)
- IMPLEMENTS → GITHUB_ISSUE `249` (Issue #249 — extends in-process agent platform's AR-execution surface (wrapper deploys to every agent))
