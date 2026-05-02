# ADR-020: Wazuh agents run in-process on the target containers; sidecars only for upstream-image carve-outs

## Status

accepted

## Date

2026-05-02

## Context

The v6.3.0 work (CHANGELOG 2026-05-01) added six **Wazuh sidecar** containers — `wazuh-sidecar-{webapp,fileshare,ad,dns,db,suricata}` — built from `containers/wazuh-sidecar/`. Each sidecar mounts its target's log volume read-only and ships the contained log files to the Wazuh manager. This solved log-shipping for the five target services that ship no agent in the upstream image, and was a tactical step rather than a final architecture.

The sidecar pattern has a structural limitation that became load-bearing once the lab's prevention story crystallised in [ADR-019](adr-019-suricata-ids-only-prevention-via-wazuh-ar.md): **a sidecar's iptables operate on the sidecar's own network namespace, not the target's**. Wazuh active-response (AR) on a sidecar can install a `firewall-drop` rule, but the target's traffic transits a different namespace and is unaffected — the rule is real, but irrelevant. ADR-019 chose Wazuh AR as the lab's packet-level prevention layer (NFQ-on-Suricata wasn't viable cleanly under modern Docker); for AR to do anything, the agent must run **in the namespace whose traffic must be controlled**, which means in-process on the target.

Issue [#248](https://github.com/Brad-Edwards/Brad-Edwards/aptl/issues/248) is the implementation. This ADR records the agent-placement decision as a permanent design rule, so future containers added to the lab pick the right pattern by default.

## Decision

**In-process Wazuh agent is the default placement on every APTL target container.** The sidecar pattern is reserved for the narrow case where the upstream image's constraints (immutable / no first-party agent package / hardened user-isolation) make in-process disproportionately costly.

### Default — in-process

The four target containers `webapp`, `fileshare`, `ad`, `dns` run `wazuh-agent` directly inside the container's own namespace, supervised by `supervisord` alongside the primary service. Each Dockerfile uses the shared bootstrap layer at `containers/_wazuh-agent/`:

- `install.sh` — apt-repo + key + `wazuh-agent=4.12.0-1` install. Run once during image build.
- `wazuh-agent.sh` — runtime bootstrap: wait for manager auth port, render `ossec.conf` from template, register via `agent-auth -F 1` (replaces stale same-name records), start the agent, exec `tail -F` on `ossec.log` so the supervising process (docker for sidecar, supervisord for in-process) owns lifecycle.
- `ossec.conf.template` — base ossec.conf with `__WAZUH_MANAGER__` / `__AGENT_NAME__` / `__LOCALFILE_BLOCKS__` substitution.

Each target's compose entry adds:
- `cap_add: [..., NET_ADMIN]` so the agent's AR can call `iptables` on the container's own namespace.
- `WAZUH_MANAGER` / `AGENT_NAME` / `LOG_PATHS` / `LOG_FORMAT` env vars.
- `depends_on: { wazuh.manager: service_healthy }`.
- Memory limit lifted to 512m where the previous limit (128–256m) wouldn't fit agent + primary service together.

Each target's image build context is the repo root (so the Dockerfile resolves both `containers/_wazuh-agent/...` and `containers/<name>/...`).

### Carve-out — sidecar retained

The `db` container uses upstream `postgres:16-alpine`. Bringing the agent in-process would require either rebuilding postgres on a glibc base or maintaining a custom alpine wazuh-agent build (no first-party Wazuh alpine package exists). Both options exceed the value of in-process AR for db specifically — postgres is a target of credential-related attacks, not of the network-layer attacks AR is best at blocking. `wazuh-sidecar-db` continues to ship db's `pg_log/postgresql.log` to the manager via the existing pattern.

The `suricata` container's deployment is governed separately by ADR-019 (Suricata stays IDS-only). Its sidecar (`wazuh-sidecar-suricata`) ships `eve.json` to the manager and is unaffected by this ADR.

### Future containers

Any new container added to the lab — regardless of who is adding it — defaults to in-process Wazuh agent. The sidecar pattern is invoked only when:
- the upstream image cannot be modified, AND
- there is no in-process path that fits within image-build cost (substantial extra image size, package-source unavailability, or user-isolation conflicts).

Document the carve-out in CHANGELOG and link back to this ADR. Don't extend the sidecar fleet without that justification.

## Consequences

### Positive

- **AR works.** Every in-process target's `iptables -L` is the same namespace as its primary service, so AR-installed `firewall-drop` rules block real traffic.
- **One source of truth.** `containers/_wazuh-agent/` is shared between in-process targets and the remaining sidecars — a fix in either path is a fix everywhere.
- **Uniform daemonization.** All four in-process targets run supervisord. `ad` already had it; webapp/fileshare/dns gained it as part of #248. New programs added in future (rsyslog tweaks, additional collectors) drop in cleanly.
- **Operational footprint shrinks.** Four sidecar containers are removed from the lab. The remaining two are explicit carve-outs, not the default.
- **Aligns with #249.** AR command/block wiring lands on top of in-process agents without any further topology work.

### Negative

- **Memory bumps.** webapp/fileshare/dns moved from 256m or 128m to 512m. The agent + service combination needs the headroom; on resource-constrained hosts the lab's total memory ceiling is ~500MB higher than before.
- **Dockerfile complexity.** Each target Dockerfile now installs supervisor + wazuh-agent and copies the shared bootstrap. The trade-off is uniform supervised lifecycle across targets, which the maintainability gain pays back.
- **Build context shift.** The four target images (and the remaining two sidecar images) build from repo root rather than per-container subdirectory. Image cache invalidation is slightly more sensitive — a change anywhere in the root context can re-run the COPY layers — but the affected files are scoped to `containers/...` and `.dockerignore` excludes `docs/`, `.git`, `node_modules`, etc.

### Risks

- **In-process agent crashes affect the target's container restart loop.** Mitigation: supervisord's `autorestart=true` + `startretries=10` on the agent program restart it independently; the primary service is a separate program and is not restarted.
- **Postgres carve-out becomes load-bearing.** If a future attack scenario requires AR on db (e.g., rate-limit a credential-spray source), the carve-out blocks it. Mitigation: track the postgres-with-agent custom-image work as a separate issue; this ADR documents that it's a known gap.
- **NET_ADMIN inside intentionally-vulnerable targets is a deliberate trust trade-off.** Granting NET_ADMIN to webapp / fileshare / ad / dns is the minimum viable capability for AR's `firewall-drop` to work on the target's own namespace, but it also means an attacker with code execution inside one of these containers can `iptables -F` to undo any active-response drop the manager just installed. The lab's threat model accepts this: (1) lab targets are intentionally vulnerable, so RCE-as-starting-condition is expected; (2) AR is one prevention layer of several — Wazuh continues to log the attacker's `iptables` activity, Suricata IDS detects the network signatures, MISP/SOAR carry the indicator forward — so a flushed iptables doesn't blind the SOC; (3) the alternative (sidecars) was *functionally broken* for AR — the rule fired but never affected the target's traffic, so "the attacker can flush" is a strict improvement over "AR doesn't work at all". For non-lab production deployments this trade-off is unacceptable and a separate trust boundary (host-firewall enforcement, BPF-based lockdown) would be required.

## Related

- [#248](https://github.com/Brad-Edwards/aptl/issues/248) — implementation issue (closed by this ADR).
- [#249](https://github.com/Brad-Edwards/aptl/issues/249) — AR `<command>` + `<active-response>` wiring with kali-IP carve-outs. Builds on this ADR's in-process agents.
- [ADR-019](adr-019-suricata-ids-only-prevention-via-wazuh-ar.md) — chose Wazuh AR as the prevention layer; this ADR is the precondition that makes it work.
- [ADR-002](adr-002-wazuh-siem.md) — original Wazuh selection rationale; the "Dual Log Collection" subsection is updated with a forward-pointer to this ADR.
