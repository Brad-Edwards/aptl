# TechVault SDL Scenario-vs-Delivery Classification Audit

Issue: APTL #369

This audit applies the corrected classification rule from
Brad-Edwards/aces#395, Brad-Edwards/aces#397, and Brad-Edwards/aces#399:
state on a node inside the realized range is scenario state. The delivery
layer is the control plane, backend runtime, host kernel, and orchestration
machinery around the range, not software, files, services, identities, mounts,
or network behavior exposed on range nodes.

The audit output is a list of facts-with-evidence. It does not decide whether
each fact should be fixed by a TechVault SDL update, an upstream ACES surface,
or a deliberate exclusion.

## Scope Notes

- The issue body named `webapp`, `db`, `shuffle-backend`, `kali`, switch
  nodes, and `wazuh-manager`. The current `scenarios/techvault.sdl.yaml` also
  contains `ad`, so this audit includes `ad` as current encoded SDL state.
- `shuffle-backend` has a committed inventory bundle but is not currently a
  node in `scenarios/techvault.sdl.yaml`.
- Host-side Docker bridge mechanics, operator UI/backend commands, runstore
  persistence, snapshots, and generated secret material remain delivery or
  control-plane concerns. The findings below target node-internal or
  participant-observable range state.

## Findings

### SCA-001: `shuffle-backend` inventory facts are absent from the TechVault SDL

The `shuffle-backend` inventory bundle records participant-observable service,
runtime, trust, package, and vulnerability facts, but the current TechVault SDL
has no `nodes.shuffle-backend` or `infrastructure.shuffle-backend` entry.

| Fact | Evidence | Current disposition | Audit result |
| --- | --- | --- | --- |
| Upstream image identity and digest | `docs/aces/inventory/shuffle-backend/mapping-ledger.yaml` fact `shuffle-backend.image.identity`; `docker-compose.yml` service `shuffle-backend` | Ledger says `encoded`; SDL has no node | Under-specified in the current SDL. |
| Alpine OS version | Ledger fact `shuffle-backend.os.version` | Ledger says `encoded`; SDL has no node | Under-specified in the current SDL. |
| Security-network address and aliases | Ledger fact `shuffle-backend.network.identity`; Compose service at `172.20.0.20` | Ledger says `encoded_with_caveat`; SDL has no infrastructure entry | Under-specified in the current SDL. |
| API listener on TCP 5001 | Ledger fact `shuffle-backend.api.listener` | Ledger says `encoded`; SDL has no service entry | Under-specified in the current SDL. |
| Persistent `/shuffle-database` mount | Ledger fact `shuffle-backend.data.mount`; `docker-compose.yml` volume `shuffle_data:/shuffle-database` | Ledger says `blocked_by_aces_gap` to ACES #354 | Stale gap marker: later TechVault nodes now use typed `runtime.mounts`. |
| Writable Docker socket bind | Ledger fact `shuffle-backend.docker.socket`; `docker-compose.yml` bind `/var/run/docker.sock:/var/run/docker.sock` | Ledger says `blocked_by_aces_gap` to ACES #354 | Node-internal trust/control surface remains unencoded. |
| PID 1 process identity | Ledger fact `shuffle-backend.process.identity` | Ledger says `blocked_by_aces_gap` to ACES #354 | Stale gap marker: later TechVault nodes now use `runtime.process`. |
| OS package and Go module inventory | Ledger fact `shuffle-backend.package.inventory` | Ledger says `blocked_by_aces_gap` to ACES #354 | Stale gap marker: later TechVault nodes now use runtime package/dependency fields. |
| Trivy vulnerability state | Ledger fact `shuffle-backend.vulnerability.scan-state` | Ledger says `blocked_by_aces_gap` to ACES #354 | Stale gap marker: later TechVault nodes now use `runtime.package_vulnerabilities`. |

Classification note: these are not host orchestration facts merely because the
evidence was captured with Docker. They are facts about the realized
`shuffle-backend` range node or interfaces mounted into that node.

### SCA-002: `wazuh-manager` is encoded as a skeletal node despite richer range-visible state

The current SDL records `nodes.wazuh-manager` with `type`, `os`, `source`, and
three services, plus one `security-net` infrastructure link. The Compose
service and parity inventory show richer participant-observable SOC node state.

| Fact | Evidence | Current SDL state | Audit result |
| --- | --- | --- | --- |
| Wazuh API on TCP 55000 | `docker-compose.yml` service `wazuh.manager` publishes `55000:55000`; healthcheck curls `https://localhost:55000` | `nodes.wazuh-manager.services` lists 1514/tcp, 1515/tcp, and 514/udp only | Under-specified service surface. |
| Multi-network placement | `docker-compose.yml` attaches `wazuh.manager` to `aptl-security` (`172.20.0.10`), `aptl-dmz` (`172.20.1.10`), and `aptl-internal` (`172.20.2.30`) | `infrastructure.wazuh-manager.links` contains only `security-net` | Under-specified network surface. |
| Runtime config, entrypoint, healthcheck, resource, and volume state | `docker-compose.yml` service `wazuh.manager`; parity rows `defconf.wazuh_cluster`, `defconf.wazuh_indexer`, and `defconf.wazuh_dashboard` | No `runtime` block for `wazuh-manager` | Node-internal SOC state is still routed as backend/defensive-stack realization in the audit inventory. |
| Custom decoders and rules mounted into the manager | `docker-compose.yml` mounts `samba_decoders.xml`, `postgresql_decoders.xml`, `ad_rules.xml`, `webapp_rules.xml`, `suricata_rules.xml`, and `database_rules.xml`; parity row `defconf.wazuh_cluster` | No SDL content/runtime inventory for these manager-local files | Participant-observable defensive content is under-specified. |

Classification note: generated credentials and host-side certificate material
remain governed by ADR-028, ADR-029, and ADR-034. The finding is about the
range-node service/configuration surfaces and non-secret rule/decoder content,
not raw secret values.

### SCA-003: Switch-node `internal` flags do not match Compose network evidence

The SDL now includes the four switch nodes and CIDR/gateway properties, so the
old wholesale classification of network topology as backend-only no longer
holds. The current SDL still mismatches the Docker Compose network flags that
drive participant-observable egress behavior.

| Network | Compose evidence | Current SDL evidence | Audit result |
| --- | --- | --- | --- |
| `aptl-security` / `security-net` | `docker-compose.yml` declares bridge/IPAM, no `internal: true` | `infrastructure.security-net.properties.internal: true` | SDL over-specifies isolation compared with Compose. |
| `aptl-dmz` / `dmz-net` | `docker-compose.yml` declares `internal: true` | `infrastructure.dmz-net.properties` omits `internal` | SDL under-specifies isolation. |
| `aptl-redteam` / `redteam-net` | `docker-compose.yml` declares `internal: true` | `infrastructure.redteam-net.properties` omits `internal` | SDL under-specifies isolation. |
| `aptl-internal` / `internal-net` | `docker-compose.yml` declares `internal: true` | `infrastructure.internal-net.properties.internal: true` | Matches. |

Classification note: the Docker bridge implementation is delivery state, but
whether a range segment is internally isolated affects participant-visible
connectivity and belongs in the scenario audit surface.

### SCA-004: Parity inventory still contains broad backend classifications for split scenario surfaces

Several parity rows classify whole surfaces as `aptl_backend_responsibility`
even though current SDL and inventory evidence have already moved part of those
surfaces into scenario state.

| Row | Current category | Evidence that the row is too broad | Audit result |
| --- | --- | --- | --- |
| `compose.network.aptl-security`, `compose.network.aptl-dmz`, `compose.network.aptl-internal`, `compose.network.aptl-redteam` | `aptl_backend_responsibility` | `scenarios/techvault.sdl.yaml` has switch nodes and infrastructure CIDR/gateway fields for each segment | Row conflates scenario segment facts with backend bridge realization. |
| `compose.profile.enterprise` | `aptl_backend_responsibility` | `webapp`, `db`, and `ad` are now SDL nodes with runtime inventory fields | Row mixes profile-toggle delivery behavior with scenario node membership. |
| `compose.profile.soc` | `aptl_backend_responsibility` | `wazuh-manager` is an SDL node and `shuffle-backend` has an inventory bundle; SOC services are range nodes for blue/purple participants | Row mixes profile-toggle delivery behavior with scenario SOC node facts. |
| `compose.volumes.summary` | `aptl_backend_responsibility` | `runtime.mounts` are encoded for `webapp`, `db`, `kali`, and `ad`; Shuffle and Wazuh persistent volumes remain node-local state | Row treats all named volumes as backend realization even when mounted content/state is participant-observable. |
| `compose.service.webapp` | `aces_sdl`, but `blocking_followup: "#321 / #324"` | `scen.techvault.webapp-inventory` says the current SDL consumes ACES #363 through #368 with no known remaining expressivity blocker | Row metadata is stale relative to the webapp inventory row and tests. |

Classification note: this is an audit-metadata finding. It does not require
changing every row in place here; it records where downstream reconciliation
should split delivery choices from scenario facts.

## Non-Findings

The following current inventory bundles did not show the original
"backend-specific deployment detail" misclassification pattern for their
catalogued facts:

| Artifact | Audit result |
| --- | --- |
| `docs/aces/inventory/webapp/` and `nodes.webapp` | Runtime mounts, filesystem inventory, container host/security state, local identity, network realization, application surface, process set, environment, capability policy, packages, dependency manifests, and package vulnerabilities are encoded. The remaining local-account caveat distinguishes curated top-level scenario accounts from full observed Linux identity under `runtime.local_identity`. |
| `docs/aces/inventory/db/` and `nodes.db` | PostgreSQL runtime, logical database state, mounts, filesystem inventory, process set, environment, capability/restart/resource policy, package inventory, local identity, and vulnerabilities are encoded. The filesystem caveat is a capture-boundary statement, not a delivery-layer classification. |
| `docs/aces/inventory/kali/` and `nodes.kali` | The previous `init_process`, `seccomp_profile`/`security_opt`, `process_overrides`, and `ssh_servers` blockers have been consumed. Remaining caveats cover degraded audit readiness evidence, scanner-source limits, and the distinction between curated top-level accounts and full local identity inventory. |
| `docs/aces/inventory/ad/` and `nodes.ad` | AD runtime, identity authority state, filesystem inventory, process set, environment, network, packages, vulnerabilities, relationships, and curated accounts are encoded. Caveats preserve evidence-size and scanner-output boundaries rather than routing node state to delivery. |

## Evidence Reviewed

- `scenarios/techvault.sdl.yaml`
- `docker-compose.yml`
- `docs/aces/parity-inventory.yaml`
- `docs/aces/inventory/asset-inventory-methodology.md`
- `docs/aces/inventory/webapp/README.md`
- `docs/aces/inventory/webapp/mapping-ledger.yaml`
- `docs/aces/inventory/db/README.md`
- `docs/aces/inventory/db/mapping-ledger.yaml`
- `docs/aces/inventory/shuffle-backend/README.md`
- `docs/aces/inventory/shuffle-backend/mapping-ledger.yaml`
- `docs/aces/inventory/kali/README.md`
- `docs/aces/inventory/kali/mapping-ledger.yaml`
- `docs/aces/inventory/ad/README.md`
- `docs/aces/inventory/ad/mapping-ledger.yaml`
