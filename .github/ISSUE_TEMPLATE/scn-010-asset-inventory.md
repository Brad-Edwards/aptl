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

Use the ACES-owned methodology at:
https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md

The ACES methodology or expressivity issue this depends on
(Brad-Edwards/aces#<ISSUE>) MUST already exist and be linked. If it doesn't,
file that first.
-->

## Summary

Apply the ACES asset-inventorying methodology to the `<ASSET>` container as
realized in a fresh `aptl lab start`, capture the inventory at experiment
grade, and encode every observable fact directly in
`scenarios/techvault.sdl.yaml`. Referenced source packages and supporting
artifacts are evidence/provenance only; they are not substitutes for SDL
expression.

**Snapshot point**: steady state *after* `aptl lab start` has fully
completed and the container has reached its operational state. The target
is complete participant/agent-observable steady-state parity, sufficient
to reproduce this asset bit-for-bit (where bit-identity is possible) or
behaviorally (where it is not). Time dynamics and attack-induced changes
may be owned by separate linked work, but every fact observable at the
snapshot point is in scope here and must be encoded or blocked by a
specific ACES expressivity issue.

## Identifying information

- **Container (docker-compose service)**: `<ASSET>`
- **Image source**: `<IMAGE>` (registry tag for upstream images; for custom
  builds, `containers/<DIR>/`)
- **Compose profile**: `<PROFILE>` (e.g. `enterprise`, `soc`, `wazuh`,
  `mail`, `dns`, `fileshare`, `victim`, `kali`, `reverse`)
- **Family**: `<FAMILY>` (see template comment)
- **Parent tracker**: #317
- **Requirement**: SCN-010
- **Depends on**: ACES methodology or expressivity issue Brad-Edwards/aces#<ISSUE>
  (and any other in-flight gap issues this asset surfaces)

## Scope

Apply every dimension named by the ACES asset-inventorying methodology:
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>.
At minimum:

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
- **Filesystem inventory at steady state**: all participant/agent-observable
  paths, metadata, permissions, ownership, checksums/content references,
  configuration files, fixture content, certificates, pre-seeded data,
  agent installers, source, templates, static assets, generated startup
  artifacts, logs, caches, runtime files, and volume contents present at
  the snapshot point. Do not exclude logs, caches, generated state, or
  runtime-created state solely because they are transient; record stability
  limits and encode the observable shape, or file/link a blocking ACES
  expressivity issue.
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

The inventory is steady-state. Time dynamics and attack-induced transitions
may be covered by separate linked work, but any observable state present at
the steady-state snapshot, including log volumes, caches, generated files,
volume contents, and ephemeral runtime telemetry, must be encoded or
blocked by a specific ACES expressivity issue rather than silently excluded.

## Absolute Observable-Parity Gate

This issue is not complete until the TechVault ACES SDL expresses every
fact that a participant, adversary, defender, autonomous agent, tool,
evaluator, or harness could observe from inside the realized range for
this asset.

Parity means full observable parity. It is not relevance-filtered. It is
not limited to facts needed by APTL's current implementation, not limited
to load-bearing behavior, and not satisfied by storing evidence outside
the SDL.

Evidence bundles, checksums, source trees, Docker/Compose files,
screenshots, logs, inventories, comments, and mapping ledgers are proof
inputs only. They are not substitutes for SDL expression. If an observable
file, config, package, version, environment value, route, user, permission,
process, service, vulnerability, relationship, log path, filesystem entry,
credential fixture, or scanner finding is within this issue's scope, then
the SDL-backed spec must encode it directly using ACES.

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
- "Representative subset" for packages, files, vulnerabilities, processes,
  configs, env, services, routes, users, permissions, logs, filesystem
  state, or scanner findings.
- "Relevant fields encoded", "load-bearing fields encoded", or
  "implementation-important fields encoded".
- "APTL cannot consume it yet" as a reason to omit SDL content.
- "Out of scope" for any in-scope fact observable from inside the range
  unless a separate linked issue owns that observable surface and blocks
  final SCN-010 parity.

Completion checklist:

- [ ] Enumerated every participant/agent-observable fact for this asset.
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

- Inventory captured under `docs/aces/inventory/<ASSET>/` as a frozen
  artifact, following the methodology's named artifact shape. Every
  claim cites the source it was observed at (provisioner line,
  `docker inspect` output, `dpkg -l` line, file checksum, etc.).
  Reviewer can re-run the cited commands and reproduce each claim.
- All inventory surfaces that ACES can express today are encoded directly
  in `scenarios/techvault.sdl.yaml`. Source packages, Dockerfiles, Compose
  files, checksums, evidence artifacts, and ledger rows are proof inputs
  only, not substitutes for SDL expression.
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
- Traceability link added in the GRC workflow platform: SCN-010 ← `docs/aces/inventory/<ASSET>/`.
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
- The inventory does NOT by itself cover behavior over time,
  attack-induced transitions, or later operator-driven runtime changes.
  Any state present at the steady-state snapshot is still in scope. If a
  dynamic surface is excluded, link the issue that owns it and record the
  limit.
- Any surface where the inventory could not be fully resolved (closed
  upstream source, opaque image, undocumented behavior) must be flagged
  in the inventory artifact as a known limit, not silently elided.
