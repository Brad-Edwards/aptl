# ADR-019: Suricata stays IDS-only; packet-level prevention via Wazuh active-response

## Status

accepted

## Date

2026-05-02

## Context

[Issue #247](https://github.com/Brad-Edwards/aptl/issues/247) set out to switch Suricata to inline IPS via Netfilter Queue (NFQ) so `drop` signatures in `local.rules` would actually drop packets at the kernel rather than emit alerts while the SYN/ACK still completed. The premise was that for the purple-loop lab to demonstrate real prevention via the OSS defensive stack, Suricata had to do real packet drops, not just log them.

Two implementation paths were explored end-to-end on this branch. Both failed for architectural reasons that no amount of configuration tuning resolves.

### Path A — NFQ on the host's `DOCKER-USER` chain via `network_mode: host` Suricata

Suricata ran in the host's network namespace via a custom image layered on `jasonish/suricata:7.0` with `iptables-nft`, an entrypoint that discovered the four APTL bridge interfaces and inserted `iptables -I DOCKER-USER -i <bridge> -j NFQUEUE --queue-num 0 --queue-bypass` rules, and `br_netfilter` enabled per-bridge so bridged traffic transited the host's iptables. Suricata read from queue 0 with `-q 0`, `mode: accept`, `fail-open: yes`. Drop rules in `local.rules` loaded cleanly and Suricata's `nfq` stats showed `Treated/Accepted/Dropped` counters incrementing.

The drop rules did not reliably drop. `eve.json` showed the alerts fire correctly. Rule-driven drops were intermittent — a single packet might drop, but follow-up packets in the same flow continued through. The bridge transit path produced inconsistent NF_DROP enforcement.

This is upstream-acknowledged behavior, not a configuration bug. From Suricata Support [#2135](https://redmine.openinfosecfoundation.org/issues/2135), Victor Julien (Suricata maintainer):

> Sadly bridge+nfqueue has never worked well. If you need a bridge I'd advice you to look at afpacket in bridge mode.

Older reference: [Bug #228 — Suricata can't drop or reject in bridge mode](https://redmine.openinfosecfoundation.org/issues/228). The lab's four Docker bridges put Suricata-via-NFQ squarely in the broken topology class.

### Path B — L3-routing IPS via a multi-homed Suricata container with NFQ on FORWARD inside its own namespace

The textbook NFQ-IPS topology is a Linux router with NFQUEUE on its `FORWARD` chain. To get there inside Docker, Suricata would be a normal multi-homed container (no `network_mode: host`), `net.ipv4.ip_forward=1` in its namespace, and `iptables -I FORWARD -j NFQUEUE` inside the container's iptables. Packets routed across bridges via Suricata would transit `FORWARD` inside Suricata's namespace, with no Linux bridge in path inside the namespace — the upstream-broken bridge+NFQ path is avoided entirely.

A clean two-bridge POC was built: `attacker` (alpine) on `poc-redteam` (172.30.4.0/24, default route via Suricata's redteam IP), `target` (nginx:alpine) on `poc-dmz` (172.30.1.0/24), `suricata` multi-homed on both with `ip_forward=1`, NFQUEUE rule in container's FORWARD chain, single drop rule for `tcp dport 80`. The attacker's TCP SYN to the target reached the redteam bridge but never reached Suricata's namespace. `tcpdump` on Suricata's host-side veth showed zero packets during the probe; FORWARD chain counters stayed at 0; Suricata's `iptables -t raw -L PREROUTING` saw nothing.

`nft monitor trace` produced the smoking gun:

```
trace id ed82b1cd inet trace prerouting packet:
    iif "br-5864c09ee129" ether saddr 62:dc:d7:b9:c9:e5 ether daddr 4e:22:7b:7d:b6:2b
    ip saddr 172.30.4.30 ip daddr 172.30.1.20 ... tcp dport 80 tcp flags == syn

trace id ed82b1cd ip raw PREROUTING rule
    ip daddr 172.30.1.20 iifname != "br-303efebf5517"
    counter packets 27 bytes 1620
    drop (verdict drop)
```

Modern Docker (this host runs 29.4) installs anti-spoof rules in the host's `ip raw PREROUTING` chain of the form `ip daddr X iifname != bridge_X drop` — one per container IP, anchored to that container's bridge. The intent is to prevent IP spoofing across Docker networks. The side effect is to drop any cross-bridge routed traffic via a multi-homed container before it reaches the routing namespace, regardless of whether the destination MAC matches a legitimate gateway. Per-bridge `nf_call_iptables=0` does not bypass this — the rules fire on every br_netfilter-routed packet. Disabling `bridge-nf-call-iptables` globally would remove a Docker security default system-wide and is not a per-network knob.

This is a design choice in Docker's network model, not a bug. The L3-routing-IPS pattern that works on a normal Linux router does not work on a modern Docker host without disabling Docker's network protections.

### Path α — Replace Docker-managed bridges with externally-managed Linux bridges + af-packet bridge mode

The architecturally clean Suricata-side answer (Victor Julien's recommendation): use `af-packet` bridge mode where Suricata sits between two bridges as the L2 inline filter. Externally-managed Linux bridges (systemd-networkd, scripts) sidestep Docker's network management for the protected segments, so Docker's anti-spoof rules don't apply. POC not built.

This path is feasible but pushes the lab's network management out of Docker for protected segments and adds permanent operational complexity (lab boot now depends on host-level bridge setup; container network attachment becomes `network_mode: container:<other>` or external networks linked to pre-built bridges; renumbering across compose, MCP `docker-lab-config.json` files, and scenarios). Multi-day rewrite.

### Decision

Choose **path γ — Suricata stays IDS-only; packet-level prevention is delivered by Wazuh active-response on in-process Wazuh agents**. Drops happen at the target's iptables, not at Suricata's verdict.

This matches what production OSS-SOC stacks (Wazuh, Security Onion, ELK + SecOnion-style deployments) actually do: IDS detects, host firewall enforces, SOAR coordinates. It respects Docker's modern security defaults rather than fighting them. It cleanly separates detection (Suricata) from enforcement (Wazuh AR), which is also the textbook split.

Implementation lives in two existing companion issues, each its own `/implement` run:

- **[#248](https://github.com/Brad-Edwards/aptl/issues/248) — In-process Wazuh agents on webapp / fileshare / ad / dns / db** (currently sidecars). Required precondition: AR-installed iptables rules must execute in the target's network namespace, which the sidecar pattern can't deliver because each sidecar lives in its own namespace.
- **[#249](https://github.com/Brad-Edwards/aptl/issues/249) — Wire `<command>` + `<active-response>` blocks with per-target carve-outs**. Defines the trigger configuration (rule X on agent Y → run command Z) and the carve-outs that keep the purple loop functional (kali-IP whitelist at `etc/lists/active-response-whitelist`, timeout-bounded `firewall-drop` invocations, severity gates).

Together #248 + #249 deliver host-side enforcement; #247 was meant to deliver the network-side counterpart. With #247 architecturally infeasible cleanly under Docker-native networking, host-side via AR becomes the lab's full prevention story.

This ADR closes #247 with no functional change to Suricata. Suricata's `docker-compose.yml` entry, `config/suricata/suricata.yaml`, `config/suricata/rules/local.rules`, and image (`jasonish/suricata:7.0`) are unchanged from the baseline that existed before #247 was opened.

## Consequences

### Positive

- Matches production OSS-SOC patterns (detection vs. enforcement separation).
- Respects Docker's modern security model — no fighting `ip raw PREROUTING` defaults, no globally disabling `br_netfilter`, no bridge replacement.
- Suricata config stays simple. The `pcap`-on-three-networks deployment is well-understood, low-overhead, and the team's existing rule authoring workflow is unchanged.
- The detection→enforcement pipeline is explicit and inspectable: `eve.json` alert → Wazuh manager rule decode → AR command → in-process agent runs `firewall-drop` on the target. Each hop is logged.
- Kali-IP whitelist (set up in #249) prevents the purple-loop wedge that would otherwise occur if blue's first detection rule banned the lab's only attacker.

### Negative

- Suricata cannot drop a packet by itself. Blue cannot author a Suricata `drop` signature that has any effect; only `alert` rules carry meaning. ADR-019 is the canonical reference if blue asks "why doesn't my Suricata drop rule do anything?"
- The prevention path has more hops than NFQ would have (alert → manager → AR → agent → iptables). A signature-fast-path attack that completes inside the AR latency window (sub-second) will still land on the target. This is the same trade-off any IDS-plus-host-firewall stack accepts.
- Dependency chain: #249's working drops require #248 to land first. Until both ship, the lab has no real packet-level prevention.

### Risks

- **AR latency lets some attacks complete before the drop fires.** Mitigation: severity gates in #249 ensure low-noise high-confidence rules (level ≥ N) trigger AR; long-tail attacks that span multiple flows still get blocked on the second flow.
- **AR misconfiguration could wedge the lab** by blocking kali on first detection. Mitigation: #249's mandatory kali-IP whitelist, and timeout-bounded `firewall-drop` invocations so any AR-induced block auto-expires (default 60–300s per #249's design).
- **In-process agents add memory and complexity to target containers.** Mitigation: #248 explicitly bumps memory limits where 256m is current and reuses the existing `agent-auth` registration flow; the sidecar pattern is removed once in-process is verified, so net agent count stays the same.

## Related

- [#247](https://github.com/Brad-Edwards/aptl/issues/247) — this issue (closed by this ADR).
- [#248](https://github.com/Brad-Edwards/aptl/issues/248) — in-process Wazuh agents (precondition for AR enforcement).
- [#249](https://github.com/Brad-Edwards/aptl/issues/249) — AR command/block wiring with carve-outs (delivers actual drops).
- [#252](https://github.com/Brad-Edwards/aptl/issues/252) — purple-team continuity model (orchestrator-level carve-outs that complement the in-band whitelist in #249).
- [ADR-008](adr-008-soc-stack-integration.md) — Suricata IDS selection rationale, updated with a forward-pointer to this ADR.
- [ADR-021](adr-021-active-response-whitelist-via-wrapper.md) — the kali-IP whitelist mechanism that makes the AR layer this ADR chose usable in a purple loop.
- Suricata Support [#2135](https://redmine.openinfosecfoundation.org/issues/2135) — upstream "bridge+nfqueue has never worked well" reference.
- Suricata Bug [#228](https://redmine.openinfosecfoundation.org/issues/228) — older instance of the same drop-on-bridge class.
