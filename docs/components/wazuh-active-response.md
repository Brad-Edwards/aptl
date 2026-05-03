# Wazuh Active Response

Blue-facing reference for the Wazuh active-response (AR) layer in APTL — how detections trigger AR, how to wire `<active-response>` blocks per iteration, and what the kali-IP carve-out means.

## Overview

Wazuh AR is the lab's packet-level prevention path. When a Wazuh rule fires on the manager and matches an enabled `<active-response>` block, the manager dispatches a command to the affected agent's `wazuh-execd`. The agent runs the named script in `/var/ossec/active-response/bin/`, which mutates local state — typically `iptables -j DROP` against a source IP for a bounded TTL.

The architectural framing lives in three ADRs:

- **[ADR-019](../adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md)** chose Wazuh AR (over Suricata NFQ) as the prevention layer.
- **[ADR-020](../adrs/adr-020-wazuh-agents-in-process-vs-sidecar.md)** placed Wazuh agents in-process on `webapp` / `fileshare` / `ad` / `dns` so AR's `iptables` mutates the target's own namespace.
- **[ADR-021](../adrs/adr-021-active-response-whitelist-via-wrapper.md)** records the kali-IP whitelist enforcement via a standalone iptables AR script.

## Architecture

```
detection → manager rule → <active-response> block → agent's wazuh-execd
                                                          ↓
                                  /var/ossec/active-response/bin/aptl-firewall-drop
                                                          ↓
                                  consults /var/ossec/etc/lists/active-response-whitelist
                                                          ↓
                                  whitelisted on `add`? → log + exit 0 (no iptables call)
                                  otherwise → run iptables -I/-D INPUT -s <srcip> -j DROP
                                                          ↓
                                  log result to /var/ossec/logs/active-responses.log
```

The script deploys to every Wazuh agent in the lab (4 in-process + 2 sidecars = 6). It is a **standalone implementation** — not a wrapper around upstream `firewall-drop` — because Wazuh's stateful AR protocol can hold the agent→script stdin channel open after the initial JSON, and a forwarding wrapper that buffers stdin would deadlock or break the protocol. See [ADR-021](../adrs/adr-021-active-response-whitelist-via-wrapper.md) for the full rationale. The whitelist file is identical on each agent, COPYed at image build time from `config/wazuh_cluster/etc/lists/active-response-whitelist`. To update either, edit in the repo and run `aptl lab stop -v && aptl lab start`.

## Available commands

| Command | Honors whitelist? | What it does | Use case |
|---|---|---|---|
| `aptl-firewall-drop` | yes | Standalone iptables AR script; consults the kali whitelist before applying an INPUT-chain drop | Source-IP-based blocking (the canonical AR command) |
| `firewall-drop` | **no** | Bare upstream script; iptables drop without whitelist check | Avoid in this lab — use `aptl-firewall-drop` instead |
| `host-deny` | no | Appends to `/etc/hosts.deny` via TCP wrappers | SSH/SMB source bans |
| `disable-account` | no | Disables an OS or AD user account | Credential abuse / compromised account scenarios |
| `route-null` | no | Adds a null-route via `route` | Kernel-level src-IP block (more invasive than iptables) |

`<command>` blocks for all five ship in the manager config (`config/wazuh_cluster/wazuh_manager.conf`). Only `aptl-firewall-drop` honors the whitelist; if blue enables AR for `host-deny` / `disable-account` / `route-null`, kali can be affected. Scope rule_id and level conservatively when wiring those commands.

## Wiring a detection rule to AR

The manager ships **all `<active-response>` blocks disabled** by default. Blue's iter-N task is to identify a rule that fires on kali's behavior, scope it tightly (per-pattern, per-payload — not per-source-IP), and enable the corresponding AR block.

To enable AR for an existing block:

```xml
<!-- In config/wazuh_cluster/wazuh_manager.conf, find the block: -->
<active-response>
  <disabled>yes</disabled>            <!-- delete this line to enable -->
  <command>aptl-firewall-drop</command>
  <location>local</location>
  <rules_id>302010</rules_id>          <!-- webapp SQL injection -->
  <timeout>120</timeout>
</active-response>
```

Restart the manager (`docker restart aptl-wazuh-manager`) for the change to take effect.

To wire AR for a rule that doesn't yet have a block, add one matching the same shape:

```xml
<active-response>
  <command>aptl-firewall-drop</command>
  <location>local</location>
  <rules_id>YOUR_RULE_ID</rules_id>     <!-- pick a level-10+ rule -->
  <timeout>120</timeout>                <!-- 60-300s recommended -->
</active-response>
```

**Do NOT add `<level>10</level>` next to `<rules_id>`.** Wazuh OR's its matchers — see "Severity gate" below — so the combination broadens the block to every level-10+ alert. The severity gate is implicit: pick a `<rules_id>` whose underlying rule is already at level ≥ 10.

`<location>local</location>` runs the AR on the agent that triggered the rule (the most common case). Other values: `all` (every agent), `defined-agent` + `<agent_id>`, `server` (run on the manager itself), `remote` (deprecated).

## Whitelist (kali-IP carve-out)

`/var/ossec/etc/lists/active-response-whitelist` is a flat file, one IPv4 per line, `#` comment lines allowed.

**The script uses `grep -Fxq` (whole-line match), so inline comments after an IP do NOT match** — keep comments on their own lines:

```
# Active-response source-IP whitelist (kali interfaces)
# 172.20.4.30 — kali on aptl-redteam
172.20.4.30
# 172.20.1.30 — kali on aptl-dmz
172.20.1.30
# 172.20.2.35 — kali on aptl-internal
172.20.2.35
```

The shipped `config/wazuh_cluster/etc/lists/active-response-whitelist` follows this format. Adding `172.20.4.30  # kali` on one line would silently fail to match — the script would invoke `iptables` and kali could be dropped. Validate with `bash scripts/test-wazuh-ar-whitelist.sh` after editing.

The `aptl-firewall-drop` script consults this file before running any iptables operation:

- `command="add"` + srcip in whitelist → script exits 0 with a `SKIPPED for whitelisted <ip>` line in `/var/ossec/logs/active-responses.log`. No iptables change.
- `command="add"` + srcip NOT in whitelist → script runs `iptables -I INPUT 1 -s <srcip> -j DROP` (idempotent — checks `iptables -C` first to avoid duplicates). Logs `added DROP for <ip>`.
- `command="delete"` (timeout cleanup) → script **always** runs the iptables removal branch (`iptables -C` + `iptables -D` per match). Stale rules from previous invocations get reaped on schedule. Logs `removed N DROP rule(s) for <ip>`.

**Why kali is whitelisted:** without the carve-out, the moment blue enables AR against any rule kali's recon hits, kali's IP goes on every target's iptables and red can't operate in iter N+1. The whitelist forces blue to author granular rules (per-pattern, per-payload, per-behavior) rather than the coarse "ban the source" shortcut. See [ADR-021](../adrs/adr-021-active-response-whitelist-via-wrapper.md) for the architectural rationale.

## Severity gate

The `<active-response>` matchers (`<rules_id>`, `<rules_group>`, `<level>`) are **OR'd, not AND'd** in Wazuh. Putting `<level>10</level>` next to `<rules_id>302010</rules_id>` does NOT mean "rule 302010 at level 10+" — it means "rule 302010 OR any level-10+ alert," which broadens the block to every high-severity alert in the lab.

Because of this, **#249 ships every `<active-response>` block with a specific `<rules_id>` only and no `<level>` directive**. The severity gate is implicit: the rule IDs in scope (302010, 302060, 301002, 304040, 5763) are all defined at level ≥ 10 in the lab's custom rule files. Blue authoring a low-severity custom rule and pointing AR at it is the gap to watch for.

If blue wants a **catch-all level gate** (any rule at level ≥ N triggers AR), use `<level>` alone:

```xml
<active-response>
  <command>aptl-firewall-drop</command>
  <location>local</location>
  <level>12</level>             <!-- only level-12+ alerts -->
  <timeout>120</timeout>
</active-response>
```

That's much broader and rarely what you want; prefer per-rule blocks.

## Timeout strategy

Every block ships `<timeout>120</timeout>` (120 seconds). After the timeout, wazuh-execd dispatches the same command with `command="delete"`, the script runs the iptables removal branch (cleanup is unconditional, regardless of whitelist), and the iptables rule is removed. This matches real-SOC TTL pattern and prevents stale rules accumulating across iterations.

Recommended bound: 60–300s. Shorter than 60s makes blue's drops too ephemeral to be useful; longer than 300s risks the rule outliving the iteration that installed it.

## Default posture

All `<active-response>` blocks ship `<disabled>yes</disabled>`. The starting posture is **off** by design — blue's job over iters is to enable and tune them per the detection rules they author. See [#251](https://github.com/Brad-Edwards/aptl/issues/251) for the full default-defensive-posture documentation.

## `disable-account` manual procedure (AC#4 of #249)

`disable-account` mutates AD or local user accounts. Automated end-to-end testing requires a throwaway account; for lab use, the manual procedure is:

1. Create a non-Domain-Admin AD account (e.g., `disabletest@TECHVAULT.LOCAL`):
   ```
   docker exec aptl-ad samba-tool user create disabletest TestPass123!
   ```
2. Add an `<active-response>` block in `wazuh_manager.conf`:
   ```xml
   <active-response>
     <command>disable-account</command>
     <location>local</location>
     <rules_id>5760</rules_id>           <!-- example: failed AD login -->
     <timeout>180</timeout>
   </active-response>
   ```
3. Restart the manager: `docker restart aptl-wazuh-manager`.
4. Trigger a level-10 rule that names `disabletest` (e.g., 6 failed logins):
   ```
   docker exec aptl-kali kinit disabletest@TECHVAULT.LOCAL
   ```
5. Verify the account-disabled state:
   ```
   docker exec aptl-ad samba-tool user show disabletest | grep userAccountControl
   ```
6. Re-enable after the timeout, or manually:
   ```
   docker exec aptl-ad samba-tool user enable disabletest
   ```
7. Clean up: remove the AR block and the test account (`samba-tool user delete disabletest`).

## Troubleshooting

**"AR doesn't fire when I trigger the rule."** Check `<disabled>yes</disabled>` is removed. Restart the manager so the new block loads. Check `docker logs aptl-wazuh-manager | grep -i active.response` for dispatch errors. Verify the rule actually fired in `/var/ossec/logs/alerts/alerts.json`. Remember the matchers (`<rules_id>`, `<rules_group>`, `<level>`) are OR'd — if your block has only `<rules_id>` set, AR fires when that rule triggers; if you also added `<level>10</level>`, AR additionally fires on every level-10+ alert.

**"Rule fired, AR dispatched, but no iptables drop on the target."** Check the agent's `/var/ossec/logs/active-responses.log` for the script's behavior. A `SKIPPED for whitelisted` line means the carve-out engaged (intended for kali). An `added DROP` line means the script ran iptables but maybe a higher-priority chain rule overrode it; `docker exec <target> iptables -L INPUT -n -v` to see if the rule landed and is being matched. No log line at all means wazuh-execd never dispatched — check `docker exec <target> supervisorctl status wazuh-agent` and the manager's dispatch log.

**"AR drops kali on the first iter, even though it's whitelisted."** Verify `/var/ossec/etc/lists/active-response-whitelist` on the agent (not the manager) contains all three kali IPs (`docker exec <target> cat /var/ossec/etc/lists/active-response-whitelist`). Verify `<command>` references `aptl-firewall-drop` not bare `firewall-drop` (`grep -A 5 active-response /var/ossec/etc/ossec.conf` inside the manager). If both look right, run `bash scripts/test-wazuh-ar-whitelist.sh` to bisect.

**"I want AR for `host-deny` / `disable-account` against kali to also be carved out."** Currently only `aptl-firewall-drop` honors the whitelist. Generalizing the standalone-script pattern to `aptl-host-deny` / `aptl-disable-account` is recorded as future work in [ADR-021](../adrs/adr-021-active-response-whitelist-via-wrapper.md). For now, scope `<rules_id>` carefully or avoid those commands for kali-affecting paths.

## Related

- [Issue #249](https://github.com/Brad-Edwards/aptl/issues/249) — implementation issue.
- [#252](https://github.com/Brad-Edwards/aptl/issues/252) — orchestrator-side post-iter cleanup, complementary to the in-band whitelist.
- [tests/test_wazuh_active_response.py](../../tests/test_wazuh_active_response.py) — pytest assertions on the AR config + standalone script.
- [scripts/test-wazuh-ar-whitelist.sh](../../scripts/test-wazuh-ar-whitelist.sh) — manual E2E for the carve-out.
