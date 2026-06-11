# Kali Red Team Container

The Kali Linux container is the box AI agents operate against via the
APTL red-team MCP server. It carries a vanilla Kali install plus
**OBS-003 behavioural capture** (per [ADR-033](../adrs/adr-033-agent-reasoning-trace-boundary.md)):
auditd, process accounting, full per-session PTY recording via
`script(1)` with `--log-io --return`, and per-session `tcpdump`.
Captures land in a docker named volume `kali_captures:/var/log/aptl/captures`
and the MCP-red server harvests them via `docker cp` on session
close into `.aptl/runs/<run_id>/kali-side/<session_id>/` on the host
with 0600 permissions.

The container deliberately ships **no Wazuh agent, no rsyslog
forwarding to the SIEM, and no `redteam_logging.sh` helpers**. Under
the non-contamination principle, red activity must not bleed into the
blue defensive stack's awareness through the SIEM. See ADR-033 for
the full rationale.

## Container Configuration

- **Base Image**: kalilinux/kali-last-release:latest
- **Tools**: kali-linux-core, kali-tools-top10, plus impacket / ldap-utils /
  smbclient / smbmap / enum4linux / bloodhound.py for the TechVault scenario
- **OBS-003 capture stack**: auditd, acct (process accounting), tcpdump,
  bsdmainutils (provides `script(1)` for PTY recording)
- **User**: `kali` with sudo privileges
- **SSH**: Key-based authentication only (port 22, lab-internal; no host port is published);
  `AcceptEnv APTL_*` enabled so the MCP server can pass
  `APTL_SESSION_ID` / `APTL_RUN_ID` / `APTL_TRACE_ID` into the shell.
- **ForceCommand**: every `kali` user SSH session is wrapped through
  `/usr/local/bin/aptl-wrap-shell.sh`, which starts per-session
  `script` + `tcpdump` and execs the agent's command (or an
  interactive bash).

See [containers/kali/Dockerfile](https://github.com/Brad-Edwards/aptl/blob/main/containers/kali/Dockerfile) for
complete build configuration and
[containers/kali/scripts/aptl-wrap-shell.sh](https://github.com/Brad-Edwards/aptl/blob/main/containers/kali/scripts/aptl-wrap-shell.sh)
for the session wrapper.

## Network Access

- **Container IPs**: 172.20.4.30 (redteam), 172.20.1.30 (dmz),
  172.20.2.35 (internal)
- **Networks**: aptl-redteam, aptl-dmz, aptl-internal. The
  aptl-internal attachment exists so the agent can reach internal
  target hosts (db, files, ws01, dc, ns1)—NOT to reach the SIEM,
  which is no longer in scope for kali.
- **Target Access**: DMZ (webapp 172.20.1.20, mail 172.20.1.21,
  DNS 172.20.1.22) and internal (AD 172.20.2.10, DB 172.20.2.11,
  victim 172.20.2.20)
- **SSH Access**: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## OBS-003 Capture Surface

Per-session captures land on the host filesystem at
`.aptl/runs/<run_id>/kali-side/<session_id>/`. `run_id` is the
scenario's `trace_id` (from `.aptl/trace-context.json` written by
`aptl scenario start`); `session_id` is the MCP-level SSH session id
passed via `SendEnv APTL_SESSION_ID`.

| Subdir | What | Tool |
|---|---|---|
| `pty/typescript` | Full PTY recording—every keystroke + every byte of output | `script -q -f --timing` |
| `pty/timing` | Companion timing file for `scriptreplay` playback | `script --timing` |
| `pcap/session.pcap` (+ rotation) | Per-session network capture, excluding port 22 noise; rolling 1GB max per session | `tcpdump -i any -C 100 -W 10 -U` |

Two container-wide captures are also collected (not per-session yet):

- `/var/log/audit/audit.log`: auditd events for execve, connect,
  and file ops on /home/kali, /tmp, /root, /etc. Loaded from
  [containers/kali/audit/aptl.rules](https://github.com/Brad-Edwards/aptl/blob/main/containers/kali/audit/aptl.rules).
- `/var/log/account/pacct`: process accounting (who ran what, when).

Reading these:

```bash
# Replay a PTY session in real time
scriptreplay --timing=.aptl/runs/<run_id>/kali-side/<sess>/pty/timing \
             .aptl/runs/<run_id>/kali-side/<sess>/pty/typescript

# Inspect pcap
tshark -r .aptl/runs/<run_id>/kali-side/<sess>/pcap/session.pcap

# auditd events for execve
ausearch -k aptl_exec
```

## Container capabilities

The container requires:

- `NET_RAW` + `NET_ADMIN`—for tcpdump and red-team network tools.
- `AUDIT_CONTROL` + `AUDIT_WRITE`—for auditd to load the APTL
  ruleset and write events. If your kernel/runtime denies these,
  auditd will fail at start and `entrypoint.sh` logs a warning; the
  rest of the lab continues working with PTY + pcap capture only.

## MCP Integration

The red-team MCP server is in [mcp/mcp-red](https://github.com/Brad-Edwards/aptl/tree/main/mcp/mcp-red). The
shared SSH layer in [mcp/aptl-mcp-common/src/ssh.ts](https://github.com/Brad-Edwards/aptl/blob/main/mcp/aptl-mcp-common/src/ssh.ts)
opens sessions with `SendEnv APTL_*` and writes a continuous PTY tee
to `.aptl/runs/<run_id>/mcp-side/sessions/<session_id>.jsonl`—
that's the MCP-server-side witness, independent of the Kali-side
`script` recording. Tool-call records (full untruncated args +
result) go to `.aptl/runs/<run_id>/mcp-side/tool-calls.jsonl`.

**Setup:**

```bash
cd mcp/mcp-red && npm install && npm run build
```

```json
{
    "mcpServers": {
        "aptl-lab": {
            "command": "node",
            "args": ["./mcp/mcp-red/build/index.js"],
            "cwd": "."
        }
    }
}
```

See [MCP Integration](mcp-integration.md) for detailed setup
instructions.

## Experimental record redaction toggle

By default the MCP-side captures (tool-calls.jsonl, ocsf.jsonl)
redact credential-shaped values via the shared
`src/aptl/utils/redaction.py` / `mcp/aptl-mcp-common/src/redaction.ts`
helpers. For experiments where the credential IS the experimental
signal (for example testing how an agent reasons about a particular leaked
secret), set `APTL_EXPERIMENT_NO_REDACT=1` in the MCP server's env;
the redaction layer then passes values through verbatim. The toggle
defaults off, fails closed against any non-truthy value, and never
affects pcap content (pcaps are always raw wire bytes by design).

## Why no SIEM integration

Prior revisions of this container ran a Wazuh agent and forwarded
red-side activity to the Wazuh manager via rsyslog + the
`kali_redteam_rules.xml` decoder. That gave the blue stack an
artificial picture of red activity that no real defender would have.
Under [ADR-033](../adrs/adr-033-agent-reasoning-trace-boundary.md)
that pipe is removed: blue's perception layer must reflect only what
blue's own sensors detect, not what the attacker self-reports.

If a future requirement wants blue to learn red activity, the answer
is "point blue at the experimental data store" or "build a summary
tool"—not a direct red→SIEM pipe.

## Access

```bash
# Interactive shell from the host (no host SSH port is published)
aptl container shell aptl-kali

# SSH from inside the lab (e.g. from another container)
ssh -i /home/labadmin/.ssh/aptl_lab_key kali@172.20.4.30
```
