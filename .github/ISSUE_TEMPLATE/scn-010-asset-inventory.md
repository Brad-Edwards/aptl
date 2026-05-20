---
name: SCN-010 per-asset inventory
about: Inventory a single TechVault container at experiment grade for ACES SDL coverage.
title: "SCN-010 inventory: <ASSET> container (steady-state asset spec)"
labels: ["enhancement"]
assignees: []
---

<!--
Use this template when inventorying ONE container that makes up the TechVault
scenario. Replace every `<ASSET>` / `<IMAGE>` / `<PROFILE>` / `<FAMILY>`
placeholder before opening the issue.

Family is one of: target | attacker | defensive-wazuh-core |
defensive-wazuh-sidecar | defensive-soc-app | defensive-soc-backing-store.

The ACES methodology issue this depends on (Brad-Edwards/aces#<METHODOLOGY-ISSUE>)
MUST already exist and be linked. If it doesn't, file that first.
-->

## Summary

Apply the ACES asset-inventorying methodology to the `<ASSET>` container as
realized in a fresh `aptl lab start`, capture the inventory at experiment
grade, and encode the result in `scenarios/techvault.sdl.yaml` and any
referenced source packages / supporting artifacts.

**Snapshot point**: steady state *after* `aptl lab start` has fully
completed and the container has reached its operational state. Time
dynamics are out of scope; the target is a single steady-state spec
sufficient to reproduce this asset bit-for-bit (where bit-identity is
possible) or behaviorally (where it is not).

## Identifying information

- **Container (docker-compose service)**: `<ASSET>`
- **Image source**: `<IMAGE>` (registry tag for upstream images; for custom
  builds, `containers/<DIR>/`)
- **Compose profile**: `<PROFILE>` (e.g. `enterprise`, `soc`, `wazuh`,
  `mail`, `dns`, `fileshare`, `victim`, `kali`, `reverse`)
- **Family**: `<FAMILY>` (see template comment)
- **Parent tracker**: #317
- **Requirement**: SCN-010
- **Depends on**: ACES methodology issue Brad-Edwards/aces#<METHODOLOGY-ISSUE>
  (and any other in-flight gap issues this asset surfaces)

## Scope

Apply every dimension named by the ACES asset-inventorying methodology
([link to methodology spec when it lands]). At minimum:

- **Image identity**: base image registry + digest, all parent layers,
  build args used at build time.
- **Build recipe**: Dockerfile (or absence thereof for upstream images),
  every COPY / RUN / ARG / ENV line with the inputs each consumed.
- **Package manifest at build time**: `dpkg -l` / `rpm -qa` /
  `pip freeze` / `npm ls` / language-specific lockfile snapshot.
- **Patch state**: CVE inventory at snapshot time per the methodology's
  cited approach (Trivy / Grype / equivalent), with severity counts and
  per-vuln IDs.
- **First-boot / provisioning state**: every script that runs at build
  or first-start (e.g. `containers/<ASSET>/*.sh`), with inputs and the
  resulting on-disk state.
- **Runtime configuration**: env vars (declared in compose + resolved
  values, redacted per ADR-029 where they're operator secrets), exposed
  ports, capabilities, mounted volumes (bind + named), network
  attachments, healthcheck command + interval + retries + start_period,
  restart policy, ulimits.
- **Filesystem inventory at steady state**: paths + checksums for
  scenario-load-bearing content. Exclude transient state (logs,
  caches); include configuration files, fixture content, certificates,
  pre-seeded data, agent installers.
- **Identity surfaces local to this host**: local users + UID/GID,
  shells, home dirs, sudo entries, any service accounts owned by this
  container (AD users live in `ad`'s inventory, not in their consumer's).
- **Service surfaces**: every open port + protocol + bound interface;
  the application or daemon listening; readiness criteria.
- **Vulnerability inventory** (target hosts only): declared scenario
  weaknesses (the SDL `vulnerabilities` entries this host carries),
  cross-checked against the realized form (CVE state).
- **Relationships originating at this host**: which services it
  connects to (with protocol + port + auth method); which observers /
  sidecars / agents ingest from it; trust relationships it participates
  in.
- **Authored-vs-realized split**: explicit per field. Which dimensions
  are authored intent (encoded in SDL), which are realized form
  (covered by ACES EXP-722 disclosure surfaces / equivalent), which
  are provenance (covered by ACES EXP-720 / equivalent). Cite the
  methodology section that governs each.

The inventory is steady-state. Document what is deliberately excluded
(time dynamics, attack-induced state changes, log volumes, ephemeral
runtime telemetry).

## Acceptance

- Inventory captured under `docs/aces/inventory/<ASSET>/` as a frozen
  artifact, following the methodology's named artifact shape. Every
  claim cites the source it was observed at (provisioner line,
  `docker inspect` output, `dpkg -l` line, file checksum, etc.).
  Reviewer can re-run the cited commands and reproduce each claim.
- All inventory surfaces that ACES can express today are encoded in
  `scenarios/techvault.sdl.yaml` (or in a referenced source package
  under `containers/<ASSET>/` that the SDL pins by name+version).
- **ACES expressivity gaps**: every surface the inventory captured but
  ACES grammar cannot represent today has a corresponding new issue
  filed against `Brad-Edwards/aces`, with the issue URL linked from
  this issue's body. Each gap issue must cite this inventory as its
  motivating consumer.
- **APTL interpretation gaps**: every surface ACES CAN express but
  APTL backend cannot realize from declared content yet has a
  corresponding new APTL issue filed and linked from this issue. Each
  gap issue must name the SDL field(s) and the APTL boundary that
  needs to consume them.
- `pytest tests/ -q -k "not integration"` passes.
- `pre-commit run --all-files` passes.
- Traceability link added in Ground Control: SCN-010 ← `docs/aces/inventory/<ASSET>/`.
- The SCN-010 parity inventory at `docs/aces/parity-inventory.yaml` is
  updated where rows for this asset move between categories (e.g.
  `aces_schema_profile_gap` → `aces_sdl` once a corresponding ACES
  upstream issue lands; `aptl_backend_responsibility` rows updated to
  cite the realized form).

## Honesty / claims framing

- The inventory establishes a *spec* for this asset at steady state,
  cited against observed reality at a single point in time.
- The inventory does NOT itself prove byte-identical re-buildability;
  that's a separate equivalence-checker concern. It does provide the
  ground truth a future equivalence checker compares against.
- The inventory does NOT cover time dynamics, attack-induced state
  transitions, or operator-driven runtime changes. Those are out of
  scope; document them as such.
- Any surface where the inventory could not be fully resolved (closed
  upstream source, opaque image, undocumented behavior) must be flagged
  in the inventory artifact as a known limit, not silently elided.
