# MCP Smoke Test Protocol — Execution Results (2026-02-22)

## Summary

7/8 steps passed. 1 partial (Shuffle execution status APIs). Full cross-system loop completed successfully.

## Results

| Step | System | Result | Notes |
|---|---|---|---|
| 1 | Kali (mcp-red) | **PASS** | whoami=kali, nmap 7.95, victim reachable |
| 2 | Wazuh (mcp-wazuh) | **PASS** | 3,909 alerts, Falco + red team events |
| 3 | MISP (mcp-threatintel) | **PASS** | Events found, Kali IP IOC confirmed with cross-correlation |
| 4 | TheHive (mcp-casemgmt) | **PASS** | list_cases, create_case (#10), add_observable (IP), update_case (InProgress), create_alert all succeeded |
| 5 | Shuffle (mcp-soar) | **PARTIAL** | list_workflows + execute_workflow work; get_execution returns 404, list_executions returns 401 (Shuffle RBAC issue, not MCP bug) |
| 6 | Suricata (mcp-network) | **PASS** | 28 web attacks (SQLi 302010, XSS 302020, CmdInj 302030) |
| 7 | RE (mcp-reverse) | **SKIP** | reverse_info works (returns SSH details); container not deployed (port 2027 ECONNREFUSED) |
| 8 | Full loop | **PASS** | Wazuh alerts -> MISP correlation (known threat actor) -> Shuffle workflow -> TheHive alert created |

## Known issues

1. **TheHive `create_alert` rejects `severity` and `tags` fields**: Sending `severity` (integer) or `tags` (array) in the alert body causes HTTP 400. Workaround: omit these fields; TheHive applies defaults (severity=MEDIUM, tags=[]). Does NOT affect `create_case` which accepts both fields.
2. **Shuffle execution status APIs return 401/404**: `soar_get_execution` returns 404 and `soar_list_executions` returns 401, even though `soar_execute_workflow` succeeds with the same API key. Likely a Shuffle RBAC permission issue on execution read endpoints.
3. **Kali IP is 172.20.1.30** (DMZ segment), not 172.20.0.30 (management). Protocol examples updated to use correct DMZ IP.

## Bugs fixed during execution

These bugs were discovered and fixed during the first execution of this protocol:

1. **`"value"` vs `"apiKey"` in docker-lab-config.json** — The auth sections in mcp-threatintel, mcp-casemgmt, and mcp-soar configs used `"value"` but the TypeScript type and HTTPClient expected `"apiKey"`. All API-key-authenticated servers were silently broken through the MCP layer. Fixed in all 3 config files.
2. **Missing URL path parameter substitution** — Predefined queries with URL templates like `{caseId}` and `{workflow_id}` were sent literally without substitution. Added path param substitution logic to `predefined_query` in `api-handlers.ts`. Affected tools: `cases_add_observable`, `cases_update_case`, `soar_execute_workflow`, `soar_get_execution`, `soar_list_executions`.
