# UAT Issues Log — 2026-02-23

## UAT Summary

**Run ID**: `56092120f382477191a5da5aa92374bb`
**Scenario**: TechVault Enterprise Compromise (prime-enterprise)
**Duration**: 9m 48s

### Run Assembly Results
| Artifact | Status | Size/Count |
|----------|--------|------------|
| manifest.json | PASS | 1.6 KB, all required fields present |
| flags.json | FAIL | 0 flags (Issue 1) |
| scenario/definition.yaml | PASS | 27.9 KB, copy of scenario YAML |
| scenario/events.jsonl | PASS | 2 events (start + stop) |
| scenario/report.json | REMOVED | Scoring removed from lifecycle |
| wazuh/alerts.jsonl | PASS | 150 alerts collected |
| suricata/eve.jsonl | PASS | 7,899 entries (4.7 MB) |
| containers/*.log | PASS | 7 containers with output |
| agents/traces.jsonl | FAIL | Missing — MCP servers not restarted (Issue 10) |
| soc/thehive-cases.json | FAIL | Missing — TheHive auth failed (Issue 4) |
| soc/misp-correlations.json | ABSENT | No MISP key in env |
| soc/shuffle-executions.json | ABSENT | No executions in time window |

### CLI Commands
| Command | Status |
|---------|--------|
| `aptl scenario start prime-enterprise` | PASS (after Issue 2 fix) |
| `aptl scenario status` | PASS — shows run_id |
| `aptl scenario stop` | PASS — assembles run, prints path |
| `aptl runs list` | PASS |
| `aptl runs show <prefix>` | PASS — prefix matching works |
| `aptl runs path <prefix>` | PASS |

### Attack Steps Exercised
| Step | Technique | Status | Notes |
|------|-----------|--------|-------|
| 1 | Nmap recon | PASS | Webapp found on 8080 |
| 2 | SQLi login bypass | PASS | `admin'--` → 302 to /dashboard |
| 3 | Command injection | PASS | `;id` → uid=0(root) |
| 4 | Credential harvest | PASS | .env and /debug expose DB creds |
| 5 | Database dump | PASS | Customer PII + AWS keys retrieved |
| 6 | Exfiltration | PARTIAL | HTTP exfil testable, DNS tunnel not available |
| 7 | Password spray | PASS | `michael.thompson:Summer2024` valid (nxc, not crackmapexec) |
| 8 | LDAP enum | PASS | 15 users enumerated (nxc, not ldapsearch) |
| 9 | Kerberoasting | FAIL | DNS can't resolve TECHVAULT.LOCAL (Issue 8) |
| 10 | Service account abuse | BLOCKED | Depends on step 9 + impacket missing (Issue 7) |
| 11 | SMB share access | PARTIAL | Share listing works via nxc, file download needs smbclient (Issue 9) |
| 12 | SSH lateral movement | EXPECTED FAIL | Pubkey-only, needs harvested keys from prior steps |
| 13 | Group discovery | PASS | Domain Admins, IT-Admins enumerated |

---

## Issue 1: CTF Flag Collection Failed (All Containers)
- **Symptom**: `aptl scenario start` reports "Could not read user/root flag" for all 5 containers (victim, workstation, webapp, ad, fileshare)
- **Output**: "No CTF flags collected (containers may not be running)"
- **But**: All containers show `running (healthy)` in `aptl lab status`
- **Root cause hypothesis**: Flag files aren't being generated at container start. The entrypoint scripts may not be writing flags, or the flag paths in `src/aptl/core/flags.py` don't match the actual container paths.
- **Containers affected**: aptl-victim, aptl-workstation, aptl-webapp, aptl-ad, aptl-fileshare
- **Severity**: HIGH — flags are a core scoring mechanism
- **Fix needed**: Verify entrypoint scripts generate flag files, cross-check paths in `FLAG_LOCATIONS` dict against actual container filesystem

## Issue 2: `defenses` field not in ScenarioDefinition model
- **Symptom**: `aptl scenario start prime-enterprise` failed with Pydantic validation error: `Extra inputs are not permitted` for `defenses` field
- **Fix applied**: Added `defenses: dict | None = None` to `ScenarioDefinition` in `scenarios.py`
- **Status**: FIXED (this session)

## Issue 3: Webapp curl timeout from Kali
- **Symptom**: `curl -sk https://172.20.1.20:8080/` from Kali timed out after 30s
- **Context**: Webapp container shows healthy, nmap ping scan found it at 172.20.2.25 (internal) but DMZ address 172.20.1.20 may not be responding on port 8080, or HTTPS vs HTTP mismatch
- **Severity**: LOW — user error in test, not an infrastructure issue
- **Resolution**: Webapp responds on `http://` (not `https://`). `curl -sk http://172.20.1.20:8080/` works fine. HTTPS was wrong protocol.

## Issue 5: Scenario YAML references `crackmapexec` but Kali has `netexec`/`nxc`
- **Symptom**: Steps 7, 8, 10, 13 in prime-enterprise.yaml use `crackmapexec` which is not installed. Kali has `netexec` (v1.4.0) at `/usr/bin/netexec` (alias `nxc`).
- **Severity**: HIGH — 4 out of 13 attack steps have wrong tool name in commands
- **Status**: FIXED — Updated all `crackmapexec` references to `nxc` in prime-enterprise.yaml, ad-domain-compromise.yaml, and prime-scenario.md

## Issue 6: `ldapsearch` not installed on Kali
- **Symptom**: Steps 8 and 13 reference `ldapsearch` which is not installed. Only `python3-ldap3` and `python3-ldapdomaindump` are available.
- **Severity**: MEDIUM — LDAP enum steps fail as written. Can use `nxc ldap` or `ldapdomaindump` or `impacket` instead.
- **Fix needed**: Install `ldap-utils` in Kali Dockerfile, OR update scenario to use `nxc ldap` / `ldapdomaindump` for AD discovery steps

## Issue 7: `impacket` not installed on Kali
- **Symptom**: Step 9 (Kerberoasting) and step 10 (psexec) reference `impacket-GetUserSPNs` and `impacket-psexec` which are not installed. Neither `impacket-*` binaries nor the pip package exist.
- **Severity**: HIGH — Kerberoasting (step 9) and lateral movement via psexec (step 10) are blocked entirely
- **Fix needed**: Install `impacket` in Kali Dockerfile (`apt install python3-impacket impacket-scripts` or `pipx install impacket`)

## Issue 8: Kerberos fails — `TECHVAULT.LOCAL` DNS doesn't resolve from Kali
- **Symptom**: `nxc ldap --kerberoasting` found 2 SPN accounts but failed with `[Errno -2] Name or service not known` when trying to get TGT from `TECHVAULT.LOCAL:88`
- **Root cause**: Kali's `/etc/resolv.conf` points to Docker's internal DNS (127.0.0.11) which doesn't resolve `TECHVAULT.LOCAL` to the AD container (172.20.2.10). No `/etc/hosts` entry for `techvault.local` either.
- **Severity**: HIGH — Kerberoasting (step 9) is the key step for AD path. Blocks cracking service account passwords.
- **Fix needed**: Either add `TECHVAULT.LOCAL` / `DC.TECHVAULT.LOCAL` to Kali's `/etc/hosts` pointing to 172.20.2.10 (via entrypoint or docker-compose extra_hosts), OR configure the AD container as DNS server for the Kali container

## Issue 9: `smbclient` not installed on Kali
- **Symptom**: Step 11 references `smbclient` for SMB share enumeration — not installed. Only `libsmbclient0` (shared lib) is present. `smbmap` also missing.
- **Available alternative**: `nxc smb --shares` can enumerate shares
- **Severity**: MEDIUM — share enumeration still possible via nxc, but `smbclient` interactive download (`mget *`) is not available
- **Fix needed**: Install `smbclient` in Kali Dockerfile (`apt install smbclient`)

## Issue 10: MCP trace files not being written — servers running old code
- **Symptom**: `.aptl/traces/` directory exists but is empty despite multiple MCP tool calls (kali_run_command, wazuh alerts, shuffle workflows)
- **Root cause**: The MCP servers were already running (spawned by Claude Code) before the tracing code was built and deployed. They are using the old `server.js` without the `ToolTracer` wrapper. The rebuilt `aptl-mcp-common` with tracing IS installed in `node_modules` but the running processes haven't been restarted.
- **Severity**: HIGH — no agent traces will be collected for this run
- **Fix**: MCP servers must be restarted after rebuilding. This is an inherent limitation: `aptl scenario start` sets `APTL_TRACE_DIR` env and cleans stale traces, but it can't restart MCP servers owned by the IDE/Claude Code.
- **Workaround options**:
  1. Document that MCP servers must be restarted after `mcp/build-all-mcps.sh`
  2. Have the tracer use a well-known fixed path (e.g. `<project>/.aptl/traces/`) so the MCP config in `.mcp.json` can set `APTL_TRACE_DIR` once at config time
  3. Add `APTL_TRACE_DIR` to each custom MCP server's `env` block in `.mcp.json`
- **Note**: 3rd-party MCP servers (wazuh Rust binary, misp Python, thehive Go) don't use our tracer at all — only our custom Node servers (kali-ssh, reverse-sandbox-ssh, shuffle, indexer) will produce traces

## Issue 4: TheHive MCP authentication fails (401 Unauthorized)
- **Symptom**: `mcp__thehive__search-entities` returns `TheHive authentication failed: 401 Unauthorized`
- **Context**: TheHive container is `running (healthy)` per `aptl lab status`
- **Root cause hypothesis**: API key in `.mcp.json` or env is stale/expired. TheHive keys need renewal after container rebuild. The `scripts/thehive-apikey.sh` may need to be run.
- **Severity**: MEDIUM — TheHive case collection in run assembler will return empty (fault-tolerant) but data gap in telemetry
- **Fix needed**: Re-provision TheHive API key and update MCP config
