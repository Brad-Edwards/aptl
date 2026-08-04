---
id: SEC-006
title: "Verified TLS for SOC Stack Clients via Lab-Managed CA"
status: ACTIVE
type: NON_FUNCTIONAL
priority: SHOULD
wave: 3
created_at: 2026-05-03T01:10:06.093447Z
updated_at: 2026-05-18T03:43:57.248076Z
---

# SEC-006: Verified TLS for SOC Stack Clients via Lab-Managed CA

## Statement

All clients of the SOC stack (MISP, TheHive, Cortex, Shuffle), including Python service daemons (for example, aptl-misp-suricata-sync), MCP servers (mcp-threatintel, mcp-casemgmt, mcp-soar, mcp-cortex when delivered via INT-006), and CLI collectors (aptl.core.collectors), shall verify TLS using a lab-managed CA chain. SOC tools shall serve TLS certificates issued by a single lab CA generated at first startup, mirroring INF-005's pattern for Wazuh. Default posture for these clients shall be verification ENABLED, with an explicit per-client override (for example, MISP_VERIFY_SSL=false) reserved for local debugging only. SEC-004's allowance for `rejectUnauthorized: false` covers Wazuh inter-component traffic only and shall not be applied to SOC stack consumers once this requirement is ACTIVE.

## Rationale

The current SOC stack defaults to TLS verification disabled because each tool (MISP, TheHive, Cortex, Shuffle) ships self-signed certificates generated at runtime, and there is no shared trust anchor a client can verify against. A network-positioned attacker on a lab Docker network, including a compromised lab container with reach to the security network, can MITM HTTPS connections to these tools, capture API keys, and feed forged data into intel-driven detection rules and case workflows. Extending INF-005's lab CA generation to issue certificates for the SOC stack closes the gap without changing the lab's overall self-signed posture: certificates are still self-issued, but trust is anchored to a single CA that all clients trust deterministically. Codex security review of issue #250 surfaced this as the underlying gap behind the per-client `verify=false` defaults in `aptl-misp-suricata-sync`, `mcp-threatintel`, and the legacy collectors path.

## Traceability

- TESTS → TEST `mcp/aptl-mcp-common/tests/http-ca.test.ts`
- IMPLEMENTS → GITHUB_ISSUE `258` (Issue #258: SEC-006 lab-managed CA)
- IMPLEMENTS → PULL_REQUEST `309` (PR #309: SEC-006 verified TLS for SOC stack clients)
- IMPLEMENTS → ADR `docs/adrs/adr-034-lab-managed-soc-tls-ca.md` (ADR-034 Lab-Managed CA for Verified SOC Stack TLS)
- IMPLEMENTS → CODE_FILE `src/aptl/core/soc_ca.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/_soc_ca_chain.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/_soc_ca_io.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/_soc_ca_builders.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py`
- IMPLEMENTS → CODE_FILE `src/aptl/services/misp_suricata_sync/config.py`
- IMPLEMENTS → CODE_FILE `src/aptl/core/collectors.py`
- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/http.ts`
- IMPLEMENTS → CODE_FILE `mcp/aptl-mcp-common/src/config.ts`
- IMPLEMENTS → CONFIG `docker-compose.yml`
- TESTS → TEST `tests/test_soc_ca.py`
- TESTS → TEST `tests/test_collectors.py`
- TESTS → TEST `tests/test_misp_suricata_sync.py`
- TESTS → TEST `tests/test_lab.py`
