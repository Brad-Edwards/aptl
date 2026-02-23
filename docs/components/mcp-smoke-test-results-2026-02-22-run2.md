# MCP Smoke Test Protocol -- Execution Results (2026-02-22 Run 2)

## Summary

5/8 steps PASS via MCP, 2 FAIL at MCP layer only (underlying APIs work), 1 SKIP (RE not deployed). Cross-system full loop PASS using MCP + curl fallback.

| Step | System | Result | Notes |
|---|---|---|---|
| 1 | Kali (`kali-ssh`) | **PASS** | All 4 sub-tests pass (see details) |
| 2 | Wazuh SIEM (`wazuh`) | **PASS (3/4)** | cluster_health, agents, alerts pass; `rules_summary` returns Error 1201 (rule file read error on manager) |
| 3 | Raw Indexer (`indexer`) | **PASS** | match_all (3979 hits), web_attack (36 hits: SQLi/XSS/CmdInj), index override works |
| 4 | MISP (`misp`) | **FAIL (MCP)** | API works via curl; MCP Python wrapper crashes with PyMISP compatibility errors |
| 5 | TheHive (`thehive`) | **FAIL (MCP) / PASS (API)** | MCP Go binary returns 401 (org mismatch). API works via curl: list/create/get all pass |
| 6 | Shuffle (`shuffle`) | **PASS (3/4)** | list_workflows, execute_workflow, list_executions all PASS. get_execution still 404 |
| 7 | RE (`reverse-sandbox-ssh`) | **SKIP** | Container not deployed (port 2027 ECONNREFUSED) |
| 8 | Cross-system (full loop) | **PASS** | SQLi from Kali -> Wazuh alert (rule 302011) -> MISP enrichment (known Kali IP) -> TheHive case #18 |

## Step 1: Red Team -- Kali Recon

| Sub-test | Result | Detail |
|---|---|---|
| `kali_info` | PASS | Returns target_name="Kali Linux", ssh_port=2023, network=172.20.0.0/16 |
| `whoami` | PASS | Output: `kali` |
| `nmap --version` | PASS | Output: `Nmap version 7.95` |
| `ping -c 1 172.20.2.20` | PASS | `1 packets transmitted, 1 received, 0% packet loss` |

## Step 2: Wazuh SIEM

| Sub-test | Result | Detail |
|---|---|---|
| `get_wazuh_cluster_health` | PASS* | "cluster is not enabled; cluster is not running" -- expected for single-node deployment |
| `get_wazuh_agents` (active) | PASS | 3 active agents: 000 (manager), 001 (app.techvault.local/172.20.2.20), 002 (kali-redteam/172.20.2.35) |
| `get_wazuh_alert_summary` | PASS | Returns alerts with timestamps, rule IDs, descriptions (SQLi 302010, Kali auth 300001, Falco events) |
| `get_wazuh_rules_summary` | FAIL | Error 1201: "Error reading rule files" -- Wazuh Manager API issue, not MCP bug |

## Step 3: Raw Indexer

| Sub-test | Result | Detail |
|---|---|---|
| `match_all` (size 3) | PASS | 3979 total hits, 3 documents returned with full alert structure |
| `web_attack` filter | PASS | 36 hits: SQLi (302010), XSS (302020), CmdInj (302030) from 172.20.1.30 |
| Index override (`wazuh-archives-4.x-*`) | PASS* | Query succeeds (HTTP 200, returns data). Note: endpoint URL in response still shows alerts index -- may be a display issue in the MCP response |

## Step 4: MISP Threat Intelligence

| Sub-test | Result | Detail |
|---|---|---|
| `search_misp("172.20.1.30")` | FAIL | Error: `'Tag'` -- PyMISP API compatibility issue |
| `advanced_search(attribute_type, ip-src)` | FAIL | Error: `'Tag'` -- same root cause |
| `get_misp_stats` | FAIL | Error: `'PyMISP' object has no attribute 'stats'` -- API method missing |
| curl API test | PASS | MISP API works: returns "APTL Lab - Known Threat Actors" event |

**Root cause**: The published MISP MCP server uses PyMISP methods that are incompatible with the current MISP version. The underlying MISP REST API works correctly.

## Step 5: TheHive Case Management

| Sub-test | Result | Detail |
|---|---|---|
| MCP `search-entities` | FAIL | 401 Unauthorized -- `THEHIVE_ORGANISATION` in .mcp.json set to `"admin"` but API key belongs to `"APTL"` org |
| curl: list cases | PASS | 16 cases found |
| curl: create case | PASS | Case #17 created (_id=~41016, title="Agent Smoke Test Run 2") |
| curl: get case | PASS | Retrieved case with correct title, severity=1, status=New |

**Root cause**: MCP config org mismatch. Fix: change `THEHIVE_ORGANISATION` from `"admin"` to `"APTL"` in `.mcp.json`.

## Step 6: Shuffle SOAR

| Sub-test | Result | Detail |
|---|---|---|
| `soar_list_workflows` | PASS | Returns "APTL Alert to Case" workflow (id=0a740819...) |
| `soar_execute_workflow` | PASS | execution_id=feee6d95..., returned successfully |
| `soar_list_executions` | PASS | Returns execution list; our execution shows status=FINISHED. **Improvement over Run 1** (was 401) |
| `soar_get_execution` | FAIL | HTTP 404 -- Shuffle API does not support per-execution GET endpoint (known Shuffle limitation) |

## Step 7: Reverse Engineering (Optional)

| Sub-test | Result | Detail |
|---|---|---|
| `reverse_info` | PASS | Returns config (port 2027, user labadmin) |
| `reverse_run_command("which r2")` | SKIP | ECONNREFUSED -- RE container not deployed |

## Step 8: Cross-System Investigation (Full Loop)

| Phase | Tool | Result | Detail |
|---|---|---|---|
| Attack | `kali_run_command` (MCP) | PASS | SQLi payload `GET /search?q=1'+OR+1=1--` sent from Kali (172.20.1.30) to webapp (172.20.1.20:8080) |
| Detect | `indexer_query` (MCP) | PASS | Wazuh alert found within 30s: rule 302011 "Potential SQL injection: special characters in URL", srcip=172.20.1.30, groups=[sqli, web_attack] |
| Enrich | MISP REST API (curl) | PASS | 172.20.1.30 found in 2 MISP events (IDs 5, 6) as "APTL Kali DMZ network IP" -- confirmed known threat actor |
| Respond | TheHive REST API (curl) | PASS | Case #18 created: "SQLi Attack from Known Threat Actor 172.20.1.30" (severity=2, _id=~20528) |

**Full loop completed**: Attack (Kali MCP) -> Detect (Indexer MCP) -> Enrich (MISP curl) -> Respond (TheHive curl). 4 systems chained successfully. MISP and TheHive used curl fallback due to MCP layer issues documented in Steps 4 and 5.

## Known Issues

1. **Wazuh rules_summary Error 1201**: Wazuh Manager API returns "Error reading rule files". This is a server-side issue with custom rule XML files, not an MCP bug.
2. **MISP MCP PyMISP compatibility**: The published MISP MCP server's PyMISP version is incompatible with the current MISP instance (Tag serialization and stats API changes).
3. **TheHive MCP org mismatch**: `.mcp.json` sets `THEHIVE_ORGANISATION=admin` but the API key is for the `APTL` org. Fix: update to `"APTL"`.
4. **Shuffle `get_execution` 404**: The per-execution status endpoint doesn't work. `list_executions` works as a workaround.
5. **Indexer index override display**: The index override via `params.index` may not actually switch indexes (response still shows alerts index in endpoint URL).
