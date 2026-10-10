# Kali Red Team Container

`kali` is TechVault's red-team workstation: the node that AI agents and human
operators drive through the red-team MCP server. LilRAE realizes it from the
pinned TechVault pack (`resources/packs/techvault/sdl/techvault.sdl.yaml` in
the installed `raes_env_packs` package). The repository builds no image for the
node itself: `containers/kali/` has no Dockerfile, and the `kali-capture` image
described below is backend apparatus. Explicit project-tree scenarios such as
`techvault-attacker-target` declare their own, smaller `kali` node; this page
describes the pack's.

The node deliberately runs **no Wazuh agent, no rsyslog forwarding to the
SIEM, and no `redteam_logging.sh` helpers**. Under the non-contamination
principle, red activity must not bleed into the blue defensive stack's
awareness through the SIEM. See ADR-033 for the full rationale.

## Realized Node

- **Substrate**: the pack declares a Linux compute node with a systemd
  service unit and Node.js 22, so the backend starts it on
  [`aptl/generic-systemd-node22-base`](https://github.com/OpenRAE/lilrae/blob/main/containers/generic-systemd-node22-base/Dockerfile).
  That image is built from `node:22-trixie-slim` (Debian 13), not from a Kali
  Linux image, and runs systemd as PID 1.
- **Tools**: the packages the pack declares, preinstalled in that image:
  `nmap`, `sqlmap`, `hydra`, `python3-impacket`, `smbclient`, `ldap-utils`,
  `dnsutils`, `netcat-openbsd`, `curl`, `wget`, `iputils-ping`, `python3` and
  `openssh-server`.
- **Participant tools**: the pack places the `aptl-mcp-common` and `mcp-red`
  sources under `/opt/techvault/mcp`.
- **User**: `kali`. Its `authorized_keys` comes from the pack's
  `techvault-ssh-keys` generated artifact and authorizes the LilRAE
  control-plane key, `~/.ssh/aptl_lab_key` on the operator's host.
- **SSH**: under session capture, which the pack's transcript requirement
  turns on, the node's own `ssh.service` listens on `127.0.0.1:2222` and the
  capture sidecar's sshd holds port 22 (see
  [Session Capture](#session-capture)). Without a capture sidecar,
  `ssh.service` listens on port 22. The node itself publishes no host port.
- **Capabilities**: the scenario grants the node no Linux capability of its
  own.

## Network Access

- **Networks and addresses**: `redteam-net` 172.20.4.30, `dmz-net`
  172.20.1.30 and `internal-net` 172.20.2.35. All three are internal Docker
  networks with no route out of the range. The `internal-net` attachment
  exists so the agent can reach the internal targets. It is not there for the
  SIEM, which is out of scope for `kali`.
- **Targets**: in the DMZ, `webapp` 172.20.1.20 and `dns` 172.20.1.22. On the
  internal network, `ad` 172.20.2.10, `db` 172.20.2.11, `fileshare`
  172.20.2.12, `victim` 172.20.2.20 and `workstation` 172.20.2.40.

## Host Access

The pack declares `agents.red-team-operator.interactive_access.kali-ssh`.
Docker never routes host traffic onto an internal network, so LilRAE
satisfies that declaration with an operator-access relay: a separate
container (`aptl-operator-ssh-kali`, shown with the workspace prefix in
`docker ps`, for example `aptl-w<id>-operator-ssh-kali`) that publishes
`127.0.0.1:2023` and forwards it to port 22 on `kali`. The relay carries no
credentials and binds loopback only. `APTL_HP_KALI_SSH_PROXY_2023` pins the
port. Otherwise, when 2023 is in use, `aptl lab start` remaps it like every
other published port and prints the new one:

```text
[lab start] Host port 2023 for aptl-operator-ssh-kali is in use; publishing on <port> instead.
```

The pack's transcript requirement turns on session capture, so port 22 on
`kali` belongs to the capture sidecar and the relay ends at the capture
broker. The sidecar's sshd accepts `~/.ssh/aptl_lab_key`. The broker then
refuses any session that lacks the custody environment the red-team MCP
server sends: `APTL_SESSION_ID`, plus `APTL_RUN_ID` and `APTL_TRACE_ID` both
set to the active run's ID. A plain SSH login through the relay therefore
opens no shell, and `aptl container shell aptl-kali` is refused too.

These commands open a shell only on a range where no capture sidecar runs:

```bash
# SSH from the host, through the operator-access relay
ssh -i ~/.ssh/aptl_lab_key -p 2023 kali@localhost

# Interactive shell without SSH
aptl container shell aptl-kali
```

## Session Capture

The pack requires a transcript of every interactive session on the red-team
workstation (its `redteam-session-transcript` evidence requirement) and
leaves the capture mechanism to the backend. LilRAE adds the `kali-capture`
sidecar from `docker-compose.capture.yml` when the admitted capture plan
demands that transcript. Without the demand, no sidecar runs.

- The sidecar shares the `kali` container's network namespace. Its own sshd
  takes port 22 there and runs every session through the capture broker
  (`ForceCommand /usr/local/bin/broker.py`).
- When it adds the sidecar, LilRAE moves the node's own sshd to
  `127.0.0.1:2222` and authorizes the pack's Kali pivot key there. The broker
  reaches the node with that key, so sessions that arrive through the relay
  pass through the broker first.
- The broker records each session's terminal input and output under
  `/var/log/aptl/captures/<run_id>/sessions/<session_id>/frames.jsonl` in the
  `kali_captures` volume. The `kali` node does not mount that volume.
- While capture is active, `aptl container shell aptl-kali` is refused.

## MCP Integration

The red-team MCP server is [mcp/mcp-red](https://github.com/OpenRAE/lilrae/tree/main/mcp/mcp-red).
`aptl lab start` builds it. On a project with no `.mcp.json`, it creates one
from `.mcp.json.example`, whose `aptl-red` entry runs the server; later starts
refresh keys and ports in the existing file. The shared SSH layer in
[mcp/aptl-mcp-common/src/ssh.ts](https://github.com/OpenRAE/lilrae/blob/main/mcp/aptl-mcp-common/src/ssh.ts)
opens sessions with `SendEnv APTL_*` and keeps an MCP-side record of each run
in that run's `mcp-side/` directory. That directory holds the continuous PTY
tee in `sessions/<session_id>.jsonl` and the tool-call records, with full
untruncated arguments and results, in `tool-calls.jsonl`. The record is
independent of the Kali-side transcript.

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
defaults off and fails closed against any non-truthy value.

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
