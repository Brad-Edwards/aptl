# Plan for Kali MCP Logging

This document outlines a plan for adding mandatory logging to the Kali MCP server.

## Goals

- Record each tool invocation and the resulting response.
- Send these logs to the SIEM using its **external** IP address.
- Write logs into the `aptl-redteam` index in the SIEM (currently Splunk/qRadar).
- Ensure logging cannot be disabled or bypassed by any AI agent connecting to the MCP.

## Proposed Approach

1. **Central Logging Module**
   - Implement an `auditLogger` in `src/audit.ts` using a minimal dependency such as `dgram` to send syslog formatted messages over UDP/TCP.
   - Configure the destination IP/port from the lab configuration (`lab_config_json` output). The SIEM external IP will be used.
   - Provide helper functions like `logRequest(request)` and `logResponse(request, result)`.

2. **Server Integration**
   - Import `auditLogger` in `index.ts` and call it for every `ListTools` and `CallTool` handler invocation.
   - Log the user, target, command, and whether execution succeeded along with output size.
   - Log entries should be structured with the prefix `REDTEAM_LOG` so the SIEM routes them to the `aptl-redteam` index.

3. **Enforce Logging**
   - `auditLogger` should not expose any API to turn logging off.
   - Call sites will not be conditional; logging occurs before sending responses back to the client.
   - Include unit tests verifying that `auditLogger` is invoked for each tool execution.

4. **Container Forwarding**
   - The MCP container already forwards local syslog to the SIEM via rsyslog. Ensure the new logs use the same facility so they are forwarded automatically.

5. **Documentation & Deployment**
   - Update `docs/red-team-mcp.md` with configuration instructions for the SIEM IP and index.
   - Provide example log outputs and troubleshooting steps.

Implementing this will provide an immutable audit trail of all MCP usage that is stored centrally in the SIEM.
