# TechVault SDL Scenario-vs-Delivery Classification Audit

Issue: APTL #369

This audit applies the corrected classification rule from
Brad-Edwards/aces#395, Brad-Edwards/aces#397, and Brad-Edwards/aces#399:
state on a node inside the realized range is scenario state. The delivery
layer is the control plane, backend runtime, host kernel, and orchestration
machinery around the range, not software, files, services, identities, mounts,
or network behavior exposed on range nodes.

This document records the audit findings and the remediation applied in this
branch. Every actionable finding below is fixed by the TechVault SDL, parity
inventory, Shuffle ledger, or regression-test updates in this PR.

## Scope Notes

- The issue body named `webapp`, `db`, `shuffle-backend`, `kali`, switch
  nodes, and `wazuh-manager`. The current `scenarios/techvault.sdl.yaml` also
  contains `ad`, so this audit includes `ad` as current encoded SDL state.
- `shuffle-backend` has a committed inventory bundle and is now encoded as a
  node in `scenarios/techvault.sdl.yaml`.
- Host-side Docker bridge mechanics, operator UI/backend commands, runstore
  persistence, snapshots, and generated secret material remain delivery or
  control-plane concerns. The findings below target node-internal or
  participant-observable range state.

## Findings And Fixes

### SCA-001: `shuffle-backend` inventory facts were absent from the SDL

Fixed. `scenarios/techvault.sdl.yaml` now includes `nodes.shuffle-backend` and
`infrastructure.shuffle-backend` with the captured image digest, Alpine version,
security-network identity, API listener on TCP 5001, `/shuffle-database` mount,
writable Docker socket control interface, PID 1 process identity, 21 Alpine
packages, Go module manifest, and 86 Trivy package vulnerability findings.

`docs/aces/inventory/shuffle-backend/mapping-ledger.yaml` now marks all nine
Shuffle facts `encoded`; `aptl aces-inventory gaps` reports `blocked=0
triage=0`.

### SCA-002: `wazuh-manager` was encoded as a skeletal node

Fixed. `nodes.wazuh-manager` now records the Wazuh API on TCP 55000, the
Compose healthcheck as `conditions.wazuh-api-ready`, runtime environment
redaction policy, entrypoint/resource/restart policy, persistent/config mounts,
and custom decoder/rule files mounted into the manager. `infrastructure` now
attaches the manager to `security-net`, `dmz-net`, and `internal-net` with the
Compose static addresses `172.20.0.10`, `172.20.1.10`, and `172.20.2.30`.

Generated credentials and host-side certificate material remain secret/control
plane material; the SDL records the path, mount, and redaction shape without
committing raw values.

### SCA-003: Switch-node `internal` flags mismatched Compose

Fixed. The TechVault SDL now matches `docker-compose.yml` network isolation:
`security-net` omits `internal`, while `dmz-net`, `internal-net`, and
`redteam-net` carry `internal: true`.

The Docker bridge implementation remains delivery state, but segment
isolation affects participant-visible connectivity and is encoded on the
scenario infrastructure surface.

### SCA-004: Parity inventory had broad backend classifications

Fixed. `docs/aces/parity-inventory.yaml` now separates delivery toggles from
scenario-node facts:

- Added `scen.techvault.shuffle-backend-inventory`,
  `scen.techvault.wazuh-manager-inventory`,
  `compose.service.shuffle-backend`, and `compose.service.wazuh-manager`.
- Moved the four Compose network rows to `aces_sdl` ownership for switch-node
  and infrastructure metadata.
- Kept `compose.profile.enterprise` and `compose.profile.soc` as backend
  delivery toggles, with notes pointing node-local state to node-specific SDL
  rows.
- Changed `compose.volumes.summary` to a `validation_gate` row so
  participant-visible mounts are proven through per-node `runtime.mounts`
  rather than classified as backend-only by default.
- Cleared the stale `compose.service.webapp` `blocking_followup`.

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
