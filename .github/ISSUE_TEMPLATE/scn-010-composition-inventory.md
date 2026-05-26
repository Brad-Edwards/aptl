---
name: SCN-010 scenario composition inventory
about: Inventory the assembly of TechVault — how its assets compose at steady state.
title: "SCN-010 inventory: TechVault scenario composition (steady-state)"
labels: ["enhancement"]
assignees: []
---

<!--
Use this template when inventorying the cross-asset state that no single
per-asset issue owns. This issue depends on every per-asset issue plus the
ACES-owned methodology:
https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md
-->

## Summary

Inventory the assembly of TechVault from its per-asset inventories: how
the 28 substantive containers compose into a single scenario at steady
state. Capture all cross-asset state that no individual asset inventory
owns and encode every observable composition fact directly in
`scenarios/techvault.sdl.yaml`: networks, DNS, dependency graph, mounts
shared across containers, trust relationships, account-to-host mapping,
content placement, and observation chains. Supporting artifacts are
evidence/provenance only; they are not substitutes for SDL expression.

**Snapshot point**: steady state *after* `aptl lab start` has fully
completed. Time dynamics and attack-induced changes may be owned by
separate linked work, but every composition fact observable at the snapshot
point is in scope here and must be encoded or blocked by a specific ACES
expressivity issue.

## Identifying information

- **Parent tracker**: #317
- **Requirement**: SCN-010
- **Depends on**: ACES methodology or expressivity issue Brad-Edwards/aces#<ISSUE>;
  every per-asset inventory issue (SCN-010 inventory: <asset>) — list
  them here as they get filed.

## Scope

Apply the ACES asset-inventorying methodology to the inter-asset surface:
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>.
At minimum:

- **Network topology**: every Docker network at steady state (CIDR,
  gateway, internal flag, ACLs at the Docker layer), MTU, driver, IPAM
  config. Static IP assignment per container per network.
- **DNS surface**: the `techvault.local` zone and any other authored
  zones (A, PTR, SRV, CNAME records), resolver chain across hosts,
  DNS-tunneling sink configuration, fallback / split-horizon behavior.
- **Dependency graph**: compose `depends_on` edges,
  healthcheck-conditioned ordering, service-readiness dependencies
  (Wazuh agents waiting on manager enrollment, MISP → Suricata sync,
  Shuffle webhook wiring, Cortex ↔ TheHive analyzer registration, etc.).
- **Volume and bind-mount topology**: every named volume and bind
  mount, the containers that share each, the directionality of writes,
  any consistency requirements between writers and readers.
- **Trust relationships**: AD domain-join graph (who joins, what
  trusts), SMB share auth chains, TLS trust paths (SOC CA → service
  certs, target CAs), MISP API key flow, Shuffle webhook credentials,
  Cortex API integration with TheHive, Wazuh agent enrollment trust.
- **Account-to-host mapping**: every AD user and local account from
  the per-asset inventories, the host(s) it can authenticate to,
  group memberships, SPNs, password policies that apply.
- **Content placement matrix**: which fixture file / dataset / seed
  lives on which host (cross-referenced from per-asset inventories),
  write permissions, persistence model, which other hosts read it.
- **Observation chains**: which Wazuh agent / sidecar ingests from
  which host, which decoders apply, which Suricata interface taps
  which network, OTEL trace propagation paths (if any cross scenario
  boundaries), log forwarding chains.
- **Defensive workflow chains**: Wazuh alert → Shuffle workflow →
  TheHive case → Cortex analyzer flow, including the per-step
  configuration that wires them. Active-response chains
  (rule fires → AR script → target effect).
- **Authored-vs-realized split** at the composition level: which
  composition surfaces are authored intent (encoded in SDL
  `infrastructure`, `relationships`, `dependencies`), which are
  realized form, which are provenance.

## Absolute Observable-Parity Gate

This issue is not complete until the TechVault ACES SDL expresses every
composition fact that a participant, adversary, defender, autonomous agent,
tool, evaluator, or harness could observe from inside the realized range.

Parity means full observable parity. It is not relevance-filtered. It is
not limited to facts needed by APTL's current implementation, not limited
to load-bearing behavior, and not satisfied by storing evidence outside
the SDL.

Evidence bundles, checksums, source trees, Docker/Compose files,
screenshots, logs, inventories, comments, and mapping ledgers are proof
inputs only. They are not substitutes for SDL expression. If an observable
network, DNS record, route, mount, volume, trust relationship, account
binding, content placement, dependency, workflow link, observer chain, API
key flow, certificate path, service relationship, permission, log path, or
scanner finding is within this issue's scope, then the SDL-backed spec must
encode it directly using ACES.

If ACES can express it, encode it in `scenarios/techvault.sdl.yaml` and
add validation that proves it is present. If ACES cannot express it, file
one or more blocking issues in `Brad-Edwards/aces`, link them here, and do
not mark this issue complete. A filed ACES issue is a blocker, not a
waiver. After ACES merges/releases the needed expressivity, this issue
remains incomplete until the SDL is updated to use the new ACES surface and
validation passes.

APTL runtime consumption is separate. Lack of APTL support for consuming an
SDL field may require a linked APTL issue, but it never excuses missing SDL
parity and must not be used to close this issue.

Forbidden completion claims:

- "Captured in evidence" unless also encoded in SDL or blocked by a
  specific ACES expressivity issue.
- "Representative subset" for networks, DNS records, mounts, volumes,
  trusts, accounts, content placement, dependencies, workflow links,
  observer chains, permissions, logs, filesystem state, or scanner
  findings.
- "Relevant fields encoded", "load-bearing fields encoded", or
  "implementation-important fields encoded".
- "APTL cannot consume it yet" as a reason to omit SDL content.
- "Out of scope" for any in-scope fact observable from inside the range
  unless a separate linked issue owns that observable surface and blocks
  final SCN-010 parity.

Completion checklist:

- [ ] Enumerated every participant/agent-observable composition fact.
- [ ] Encoded every ACES-expressible fact in
  `scenarios/techvault.sdl.yaml`.
- [ ] Filed and linked ACES blocker issue(s) for every observable fact ACES
  cannot express.
- [ ] Verified no evidence-only observable facts remain without SDL
  encoding or an ACES blocker.
- [ ] Updated the mapping ledger so every row is `encoded` or blocked by a
  specific ACES issue.
- [ ] Did not mark this issue complete based on evidence capture,
  representative samples, summaries, relevance judgments, or APTL
  consumption status.

## Acceptance

- Composition inventory captured under
  `docs/aces/inventory/_composition/` as a frozen artifact following the
  methodology's named artifact shape. Every claim cites observed
  reality (`docker network inspect`, `docker compose config`,
  `samba-tool` output, file checksums, etc.).
- All composition surfaces ACES can express today are encoded directly in
  `scenarios/techvault.sdl.yaml` (`infrastructure`, `relationships`,
  `dependencies`, network ACLs, account `node` bindings, content `target`
  bindings, agent `allowed_subnets` / `initial_knowledge`, workflow steps,
  and any other applicable ACES fields). Evidence, external source files,
  and mapping notes are proof inputs only, not substitutes for SDL
  expression.
- **ACES expressivity gaps** at the composition level (DNS records,
  workflow-chain wiring beyond `workflows:`, trust-graph primitives,
  observation-chain primitives, volume-sharing semantics, etc.) →
  new issues filed against `Brad-Edwards/aces`, linked from this
  issue. Each gap issue cites this composition inventory as its
  motivating consumer.
- **APTL interpretation gaps** at the composition level → new APTL
  issues filed, linked from this issue.
- `pytest tests/ -q -k "not integration"` passes.
- `pre-commit run --all-files` passes.
- Traceability link added in Ground Control: SCN-010 ←
  `docs/aces/inventory/_composition/`.
- Parity inventory rows for composition-level surfaces updated where
  they move categories.

## Honesty / claims framing

- The composition inventory documents the *connective tissue* of
  TechVault as observed at steady state. It does not by itself prove
  the connections are correct or complete; subsequent validation work
  (live deployment gates, conformance suites) tests that.
- The composition inventory does NOT replace per-asset inventories;
  it depends on them. If any per-asset inventory is incomplete, the
  composition claims that build on it are correspondingly limited.
- Time dynamics, runtime workflow execution traces, and post-attack state
  may be covered by separate linked work, but observable composition facts
  present at the steady-state snapshot must be encoded or blocked by a
  specific ACES expressivity issue rather than silently excluded.
