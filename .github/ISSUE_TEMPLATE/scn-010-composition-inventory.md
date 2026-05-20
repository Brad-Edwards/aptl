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
ACES methodology issue.
-->

## Summary

Inventory the assembly of TechVault from its per-asset inventories: how
the 28 substantive containers compose into a single scenario at steady
state. Captures all cross-asset state that no individual asset inventory
owns: networks, DNS, dependency graph, mounts shared across containers,
trust relationships, account-to-host mapping, content placement, and
observation chains.

**Snapshot point**: steady state *after* `aptl lab start` has fully
completed. Time dynamics are out of scope.

## Identifying information

- **Parent tracker**: #317
- **Requirement**: SCN-010
- **Depends on**: ACES methodology issue Brad-Edwards/aces#<METHODOLOGY-ISSUE>;
  every per-asset inventory issue (SCN-010 inventory: <asset>) — list
  them here as they get filed.

## Scope

Apply the ACES asset-inventorying methodology to the inter-asset surface.
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

## Acceptance

- Composition inventory captured under
  `docs/aces/inventory/_composition/` as a frozen artifact following the
  methodology's named artifact shape. Every claim cites observed
  reality (`docker network inspect`, `docker compose config`,
  `samba-tool` output, file checksums, etc.).
- All composition surfaces ACES can express today are encoded in the
  SDL (`infrastructure`, `relationships`, `dependencies`, network
  ACLs, account `node` bindings, content `target` bindings, agent
  `allowed_subnets` / `initial_knowledge`, workflow steps).
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
- Out-of-scope surfaces (time dynamics, runtime workflow execution
  traces, post-attack state) are documented as such in the inventory
  artifact, not silently elided.
