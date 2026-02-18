# MCP Smoke Test Protocol (All APTL MCPs)

Use this protocol to quickly verify every MCP server is reachable and responsive from an AI agent.

## Preconditions

1. Start the lab:
   - `aptl lab start`
2. Build MCP servers:
   - `cd /home/runner/work/aptl/aptl/mcp && ./build-all-mcps.sh`
3. Ensure your MCP client is configured to load all APTL MCP servers.

## Test Procedure

Run each tool call below and confirm it returns a structured success response (not a connection/auth error).

### SSH-backed MCPs

1. **Red Team MCP**: call `kali_info`
2. **Reverse MCP**: call `reverse_info`
3. **Windows RE MCP**: call `mc_windows_re_info`

### API-backed MCPs

4. **Wazuh MCP**:
   - call `wazuh_api_info`
   - call `wazuh_query_alerts` with body size 1
5. **Threat Intel MCP**:
   - call `threatintel_api_info`
   - call `threatintel_get_events`
6. **Case Management MCP**:
   - call `cases_api_info`
   - call `cases_list_cases`
7. **SOAR MCP**:
   - call `soar_api_info`
   - call `soar_list_workflows`
8. **Network MCP**:
   - call `network_api_info`
   - call `network_query_ids_alerts` with body size 1

## Pass Criteria

- All 8 MCPs return successful responses for their smoke-test calls.
- No MCP returns transport, authentication, or timeout errors.
- Read-only calls complete without modifying lab state.
