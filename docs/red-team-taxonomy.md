# Red Team Activity Taxonomy

This document is the source of truth for the OCSF activity taxonomy emitted
by the Kali MCP server's red-team structured logging path. The TypeScript
classifier (`mcp/mcp-red/src/classifier.ts`) mirrors the table below — when
the table changes, the classifier and its tests change with it.

OCSF-aligned vocabulary follows the same conventions as the Python detection
and attack models in `src/aptl/core/detection.py` and
`src/aptl/core/attacks.py`, in particular the `severity_id` enum (0–6) and
the OCSF event class IDs.

The boundary that wires this taxonomy onto live MCP command execution is
captured in [ADR-027 — Red Team Structured Logging Boundary](adrs/adr-027-red-team-structured-logging.md).

## Required base fields

Every OCSF red-team record produced by `logRedTeamCommand`
(`mcp/mcp-red/src/logger.ts`) carries these fields, regardless of which
activity row matched:

| Field | Type | Source |
|---|---|---|
| `time` | number (epoch ms) | `Date.now()` at emit time — OCSF `timestamp_t` is milliseconds since the Unix epoch |
| `severity_id` | 0–6 | classifier default; bumped to MEDIUM on `success: false` |
| `category_uid` | number | OCSF event category (1 System, 3 IAM, 4 Network, 5 Discovery, 6 Application) — required by OCSF Base Event |
| `category_name` | string | OCSF category name |
| `class_uid` | number | classifier match |
| `class_name` | string | classifier match (OCSF class name) |
| `activity_id` | number | classifier match |
| `type_uid` | number | `class_uid * 100 + activity_id` |
| `metadata.product.name` | `aptl-mcp-red` | constant |
| `metadata.product.vendor_name` | `APTL` | constant |
| `process.cmd_line` | string (redacted) | input command run through the shared `redact()` helper from `aptl-mcp-common` plus a tool-agnostic short-`-p` pre-mask for non-numeric values |
| `aptl.activity_type` | string | classifier match |
| `aptl.tool` | string | leading executable token (basename); set even for the generic fallback so SIEM consumers can discriminate `curl`, `python`, `bash`, etc. |
| `aptl.tool_name` | string | MCP tool name (e.g. `kali_run_command`) |
| `aptl.agent_name` | string | `aptl-kali-red` |
| `aptl.exit_code` | number (optional) | command exit code, when known |
| `aptl.signal` | string (optional) | terminating signal name when the command was killed |

Optional fields populated by the extractor or by the caller's context:

- `attacks[]` — populated when the classification carries a MITRE technique
  (`{ technique: { uid: 'T1046' }, tactic: { name: 'Discovery' } }`).
- `dst_endpoint` — `{ ip?, hostname?, port?, ports?, port_range?, cidr? }`
  from the extractor. `port_range` carries the original spec string when a
  range expansion would exceed the cap (1024 ports).
- `actor.user.name` — `target_user` from the extractor (e.g. `ssh user@host`,
  `hydra -l user`). Only populated for tool families where the flag really
  means a target user (SSH-style, credential brute-force, host discovery);
  curl `--user user:pass` is the local Basic-auth credential pair and is
  intentionally NOT promoted into this field.
- `http_request.url` — extracted URL (run through `redact()` before
  storage so query-string secrets are masked).
- `connection_info.protocol_name` — extracted URL scheme.
- `file.path` — wordlist or output file path; scoped per tool family
  (web_discovery / credential_brute_force for `-w`, scanners for `-o`).
- `status_id` — OCSF normalized outcome: `1` (Success), `2` (Failure),
  `0` (Unknown).
- `status` — OCSF normalized outcome label (`Success` / `Failure`).
- `status_code` — source-specific outcome: numeric exit code (as a
  string) when known, or signal name for signal-terminated commands.
- `duration` — `duration_ms` from the caller.
- `aptl.session_id` — propagated from the MCP tool args.

## Activity catalogue

| activity_type | OCSF category_uid | OCSF class_uid / class_name | activity_id | type_uid | MITRE technique | MITRE tactic | Default severity_id | Tools / patterns |
|---|---|---|---|---|---|---|---|---|
| `port_scan` | 4 Network Activity | 4001 Network Activity | 1 (Open) | 400101 | T1046 | Discovery | LOW (2) | `nmap`, `masscan`, `rustscan`, `unicornscan` |
| `network_connection` | 4 Network Activity | 4001 Network Activity | 6 (Traffic) | 400106 | T1095 | Command and Control | MEDIUM (3) | `nc`, `ncat`, `socat` |
| `ssh_login_attempt` | 3 IAM | 3002 Authentication | 1 (Logon) | 300201 | T1021.004 | Lateral Movement | LOW (2) | `ssh`, `plink` |
| `credential_brute_force` | 3 IAM | 3002 Authentication | 1 (Logon) | 300201 | T1110 | Credential Access | HIGH (4) | `hydra`, `medusa`, `patator`, `crowbar` |
| `password_cracking` | 1 System | 1007 Process Activity | 1 (Launch) | 100701 | T1110.002 | Credential Access | MEDIUM (3) | `john`, `hashcat` |
| `web_attack` | 6 Application | 6001 Web Resources Activity | 99 (Other) | 600199 | T1190 | Initial Access | MEDIUM (3) | `sqlmap`, `nikto`, `wpscan`, `xsstrike` |
| `web_discovery` | 6 Application | 6001 Web Resources Activity | 99 (Other) | 600199 | T1595.003 | Reconnaissance | LOW (2) | `gobuster`, `dirb`, `dirbuster`, `wfuzz`, `ffuf`, `feroxbuster` |
| `host_discovery` | 5 Discovery | 5001 Device Inventory Info | 1 (Inventory Info) | 500101 | T1018 | Discovery | LOW (2) | `enum4linux` / `enum4linux-ng`, `smbclient`, `smbmap`, `crackmapexec` / `cme` / `nxc`, `nbtscan`, `rpcclient`, `ldapsearch`, `kerbrute`, `bloodhound-python` / `bloodhound.py` / `sharphound`, `arping`, `fping`, `fierce`, `whatweb`, `wafw00f`, `dnsenum`, `dnsrecon`, `dig`, `host`, `nslookup`, `tcpdump`, `tshark` |
| `remote_execution` | 3 IAM | 3002 Authentication | 1 (Logon) | 300201 | T1021 | Lateral Movement | HIGH (4) | `evil-winrm`, impacket family (`psexec.py`, `smbexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, `secretsdump.py`, `getuserspns.py`, `getnpusers.py`, `ntlmrelayx.py`, and the `impacket-*` aliases) |
| `network_poisoning` | 4 Network Activity | 4001 Network Activity | 6 (Traffic) | 400106 | T1557 | Credential Access | HIGH (4) | `responder`, `inveigh`, `mitm6` |
| `credential_dumping` | 1 System | 1007 Process Activity | 1 (Launch) | 100701 | T1003 | Credential Access | HIGH (4) | `mimikatz`, `pypykatz`, `lsassy`, `gosecretsdump` |
| `exploit_framework` | 1 System | 1007 Process Activity | 1 (Launch) | 100701 | T1059 | Execution | HIGH (4) | `msfconsole`, `msfvenom`, `setoolkit`, `searchsploit`, `cewl` |
| `process_execution` (fallback) | 1 System | 1007 Process Activity | 1 (Launch) | 100701 | — | — | INFO (1) | anything else; the leading executable is preserved on `aptl.tool` for SIEM discrimination |

**OCSF activity-id notes.** `web_attack` and `web_discovery` use `activity_id: 99` (Other) because OCSF Web Resources Activity defines IDs 1–7 as Create/Read/Update/Delete/Send/Import/Export — none of which semantically matches "attack" or "wordlist scan." Using Other plus the MITRE technique attached via `attacks[]` keeps SIEM consumers from seeing misleading activity labels (e.g. "Import" on a sqlmap injection). `host_discovery` uses class **5001 Device Inventory Info** under category **5 Discovery**; the prior class id `1009` was an invalid mix that schema-aware consumers could not normalize.

The classifier resolves the leading executable token by:

1. Splitting on top-level shell separators (`&&`, `||`, `;`, `|`) with
   single- and double-quote awareness. This means
   `nmap … && nc … 4444` classifies as `port_scan`, not `network_connection`,
   and `echo "nmap is …"` does **not** classify as `port_scan`.
2. Stripping a leading `sudo` and any `KEY=value` env assignments.
3. Taking the basename of the resulting executable so `/usr/bin/nmap`
   matches `nmap`.

If no entry matches the executable, the generic `process_execution`
fallback fires — the contract per ADR-027 is that every command produces
an OCSF record, never `null` or a thrown exception.

### Severity defaults

The `default_severity_id` column reflects the **best-guess sensitivity of
the activity itself**, not the success/failure of the individual run. The
logger applies one promotion rule on top:

> If `success === false` and the default is below `MEDIUM`, bump the
> emitted `severity_id` to `MEDIUM`.

Failed runs of inherently-low-signal activities (`port_scan`, `web_discovery`)
are slightly more interesting because they often indicate a target with
hardening or a misconfigured agent; high-severity activities
(`credential_brute_force`, `exploit_framework`) keep their default — they
are already at or above MEDIUM.

## Metadata extraction contract

`mcp/mcp-red/src/extractor.ts` extracts OCSF object fields from the command
string using quote-aware tokenisation. Behaviour is intentionally
conservative; if the command shape doesn't surface a field, the extractor
omits it rather than guessing.

Supported shapes:

- **IPv4** — bare addresses with octet validation. Out-of-range octets
  (e.g. `999.0.0.1`) are rejected.
- **IPv4 CIDR** — `10.0.0.0/24`. Out-of-range prefix lengths (`/99`) drop
  the CIDR but keep the bare IP.
- **IPv6** — `::1`, `2001:db8::1`, full-form addresses. Conservative
  pattern; ambiguous shapes are skipped rather than mis-attributed.
- **Ports** — `-p 22`, `--port 22` (single connection port for SSH-style
  tools), `-p 22,80,443`, `-p 1-1024` (port-list spec for scanners).
  Out-of-range ports (>65535 or 0) are rejected.
- **`host:port` positional pair** — `nc 10.0.0.1 4444` extracts both.
- **SSH-style `user@host[:port]`** — populates `target_user`,
  `dst_endpoint.ip` / `hostname`, `dst_endpoint.port`.
- **`-l <user>` / `--user <user>`** — populates `target_user`.
- **`-w <path>` / `--wordlist <path>` / `-o <path>` / `--output <path>`** —
  populates `file.path`.
- **URLs** — `https?://host[:port]/path` extracts the URL, hostname, port,
  and protocol. Used by `curl`, `sqlmap`, `nikto`, `gobuster`, `wfuzz`,
  `ffuf`, `feroxbuster`, etc.
- **Credential-tool protocol token** — `hydra … <host> ssh` records `ssh`
  as `protocol`. Recognised values: `ssh`, `ftp`, `http`, `https`, `mysql`,
  `mssql`, `postgres`, `rdp`, `smb`, `telnet`, `vnc`, `imap`, `pop3`, `snmp`.

### Credential handling

Per ADR-027, **secret values are never lifted into structured fields**.

- `hydra -p hunter2 …` — the literal password value stays only in
  `process.cmd_line`, where the shared `redact()` helper masks it.
- `hydra -P /path/to/list.txt …` — the wordlist path goes to `file.path`;
  the file's contents are never read or recorded.
- `Authorization: Bearer X`, `--password X`, cookie headers, URL userinfo,
  PEM blocks — all redacted at the `process.cmd_line` boundary by the
  shared helper.

The extractor cannot eliminate the risk that a secret token appears in an
unanticipated place. The `redact()` policy is the defense against that;
the extractor only surfaces non-secret structured fields.

## Sink and transport

Two channels run in parallel from the same `postToolHook`:

1. **OCSF SIEM stream** (`logger.ts` + `stderrJsonlSink`) — a single
   JSONL line per command, prefixed with the literal sentinel `[OCSF] `.
   External collectors can tail the MCP server's stderr and grep for
   the sentinel without parsing every line. This stream is enriched
   with classifier + extractor output for SIEM correlation.

2. **Research-grade raw capture** (`capture.ts`) — every tool call
   (not just command tools) is appended as a JSONL record to
   `<APTL_STATE_DIR>/runs/<run_id>/mcp-side/tool-calls.jsonl` (per-run
   scope; falls back to the `_unbound` sentinel when no scenario is
   active). The capture is intentionally minimal: timestamp, tool
   name, redacted args, redacted result/error, exit_code, signal,
   duration, session_id. Researchers can re-parse this stream with
   their own logic in pandas/notebooks; the parser's classification
   choices are not load-bearing for analysis.

   The legacy `APTL_RED_CAPTURE_PATH` env-var override was removed
   under ADR-033 (OBS-003 non-contamination) — its only purpose was
   bind-mounting into the wazuh-manager container for SIEM ingestion,
   which the non-contamination principle forbids.

Per ADR-027 *as amended by ADR-033*, the OCSF records are NOT
shipped to Wazuh / OpenSearch. The legacy `kali_redteam` syslog
ingestion path is removed: the Kali container no longer ships a
Wazuh agent, no longer forwards rsyslog to the SIEM, and
`config/wazuh_cluster/kali_redteam_rules.xml` /
`kali_decoders.xml` are deleted. OCSF records land in the per-run
JSONL at `<state>/runs/<run_id>/mcp-side/ocsf.jsonl` alongside the
tool-call JSONL and the PTY tee, plus a stderr `[OCSF]` line for
local development visibility.

## Cross-references

- ADR-027 — boundary, guardrails, and non-goals for OCSF schema
  work (amended by ADR-033).
- ADR-033 — Red-Side Behavioural Capture and Non-Contamination
  Boundary (supersedes the SIEM-transport portion of ADR-027).
- `src/aptl/core/detection.py` — `SeverityId` enum (Python source of truth
  for the 0–6 scale).
- `src/aptl/core/attacks.py` — MITRE technique reference shape.
- `mcp/aptl-mcp-common/src/redaction.ts` — shared TypeScript redaction
  used by `process.cmd_line` serialization.
