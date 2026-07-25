# ADR-035: Adopt ACES SDL as APTL's Scenario Authoring Surface

## Status

accepted (amended 2026-06-29, 2026-07-12, and 2026-07-19 by [ADR-046](adr-046-dynamic-aces-scenario-realization.md))

## Date

2026-05-18 (amended 2026-06-29, 2026-07-12, 2026-07-19)

## Last Updated

2026-07-19

## Status update—2026-06-29

The realization model in this ADR (specifically the Parity Inventory Boundary's
statement that topology, profiles, networks, static IPs, hostnames, volumes,
health checks, published ports, and service dependencies come from
`docker-compose.yml` and the `DeploymentBackend` inventory methods) is
**superseded by [ADR-046](adr-046-dynamic-aces-scenario-realization.md)**.
ADR-046 establishes that the compiled ACES `RuntimeModel`, interpreted through
`interpret_provisioning_plan`, is the authoritative topology source;
`docker-compose.yml` remains the realization vehicle selected by profile rather
than the topology authority.

What this ADR decided still stands: ACES SDL adoption as the canonical authoring
surface, the backend-manifest and conformance model, the `DeploymentBackend`
execution boundary, and the ACES backend integration guardrails are preserved.

## Status update—2026-07-12

**Superseded further, by [ADR-046](adr-046-dynamic-aces-scenario-realization.md)'s
Capture Inventory and Parity-Inventory Removal Addendum.** Wherever the body of
this ADR below states that `scenarios/techvault.sdl.yaml` "remains the
detailed inventory/parity evidence surface" (or the equivalent), that
statement no longer describes the repository: the capture SDL, its supporting
tree (`scenarios/techvault/`, `scenarios/aces.lock.json`), and the SCN-010
parity inventory (`docs/aces/parity-inventory.yaml` / `.md`,
`check_parity_manifest`, and the `required_surface_coverage` contract) have
all since been removed. The asset-inventory capture capability now lives in
ACES; APTL keeps only `scenarios/techvault-operational.sdl.yaml` as the
driving contract, with no separate capture/parity evidence surface behind it.
This is a point-in-time correction, not a rewrite of the decision record
below—see ADR-046 for the current state.

## Status update—2026-07-19

**Superseded further, by [ADR-046](adr-046-dynamic-aces-scenario-realization.md)'s
TechVault Full Dynamic Cutover Addendum.** The remaining compatibility statement
that `docker-compose.yml` is the profile-selected realization vehicle is no
longer true for the operational TechVault scenario. Docker Compose remains an
APTL deployment backend format, but its standalone model is derived from the
single admitted ACES execution/realization graph and is not an authoring,
topology, service-catalog, profile, or lifecycle input. A checked-in Compose
file, if retained, is a deterministic reference artifact only.

## Context

APTL and the Agentic Cyber Environment System (ACES, sibling repository at
`../aces-sdl`, `autarchy-ai/aces` upstream) are part of a single research
program. ACES is a backend-agnostic scenario description language with a
published contract surface (`backend-manifest-v2`, `runtime-snapshot-v1`,
`operation-receipt-v1` / `operation-status-v1`, workflow and evaluation
result/history envelopes, provisioning/orchestration/evaluation plan
contracts) and four published backend capability profiles
(`provisioning-only`, `orchestration-capable`, `orchestration-evaluation`,
`full-remote-control-plane`) under `contracts/profiles/backend/`. ACES's
runtime stack is `aces.core.sdl` → `aces.core.runtime` → `aces.backends.*`,
driven by a `RuntimeManager` that compiles SDL into a typed `RuntimeModel`,
plans a composite `ExecutionPlan` (provisioning + orchestration +
evaluation), and applies it against a registered `RuntimeTarget`. A backend
target is integrated by publishing a `backend-manifest-v2` claiming
conformance to a named profile and passing `aces conformance backend
--profile <name>` against that manifest.

ACES is the system whose multi-backend reproducibility story has to hold up
for the research to land; APTL is the realistic backend that proves the
contract surface against a full purple-team lab.

When this decision was written, APTL maintained its own in-tree SDL at
`aptl.core.sdl`, plus a
Pydantic-validated YAML schema at `aptl.core.scenarios` (SCN-001), with a
parallel grammar/parser/validation story tracked by DSL-001..DSL-009. The
in-tree SDL and ACES SDL both started from the Open Cyber Range SDL (the
same root), so the surfaces overlap substantially, and the in-tree fork is
already drifting in scope and naming.

Carrying two SDLs has three concrete costs:

1. **Cross-backend reproducibility—the central ACES claim—cannot be
   demonstrated using APTL scenarios** because their grammar is
   APTL-private. The research program cannot show "the same scenario ran
   on backend A and backend B" while APTL refuses to read the same
   document the other backends do.
2. **Every DSL-002..DSL-009 feature is duplicate work** against
   equivalent ACES features (variables/runtime substitution, composition,
   pre/post-conditions, CACAO/Attack Flow alignment, cleanup/rollback,
   topology declaration, user-behavior profiles).
3. **Tooling already exists in ACES**—`aces sdl resolve`,
   `aces sdl verify-imports`, `aces sdl publish`, lockfiles
   (`aces.lock.json`), OCI module distribution, MCP server, conformance
   runner—and would have to be rebuilt in-tree to reach parity.

Implementation status as of 2026-06-25: public lab startup now defaults to the
ACES-authored operational TechVault SDL through `start_aces_scenario()`,
`scenarios/catalog.json`, and the ACES runtime manager. APTL has since promoted
its backend manifest and gates beyond the Phase A bootstrap claims. Remaining
work under issue #530 is reconciliation cleanup: remove or quarantine legacy
APTL SDL/YAML surfaces and update stale docs/tests so they cannot be mistaken
for current authoring or runtime authorities.

## Decision

APTL adopts ACES SDL as its canonical scenario authoring surface and
implements an ACES backend target that wraps APTL's existing lab.

Specifically:

- Authored scenarios are ACES SDL documents parsed by `aces_sdl.parse_sdl`
  / `parse_sdl_file` against ACES's published schemas and semantic
  validators.
- APTL implements one `RuntimeTarget` registered into the ACES runtime
  target registry and publishes a `backend-manifest-v2` from
  `src/aptl/backends/aces_manifest.py:create_aptl_manifest()`. The manifest
  and conformance gates are the source of truth for the current backend
  profile claim; do not copy stale profile names from historical planning text.
- APTL's CLI delegates `aptl lab start` and friends through the ACES
  `RuntimeManager` lifecycle (compile → plan → validate → apply → start
  orchestrator/evaluator → stop) instead of the current imperative Python
  lifecycle.
- APTL's published backend manifest is validated by the ACES target
  conformance runner and the published `aces conformance backend --profile
  <current-profile>` CLI path used by the static/live gates.
- During Phase A, the legacy `aptl.core.sdl` parser and `scenarios/*.yaml`
  Pydantic path remained functional. The `aces_sdl`
  dependency, the ACES backend target, and the ACES TechVault scenario
  land as a *parallel* path during Phase A.
- At cutover (Phase B, a single PR), the public startup path flipped to the
  ACES-authored operational TechVault SDL
  (`scenarios/techvault-operational.sdl.yaml`). The deeper
  `scenarios/techvault.sdl.yaml` remains the detailed inventory/parity
  artifact rather than the runtime boot contract. Legacy `scenarios/*.yaml`
  moved to `scenarios/archive/` as strictly reference-only material (not
  loaded by any runtime path), `aptl.core.sdl` is deleted,
  `aptl.core.scenarios` remains only as shared session/continuity exception
  types, and Pydantic `ScenarioDefinition` models are
  deleted.

## Backend Profile Choice

APTL targeted `provisioning-only` initially because that profile requires only
`backend-manifest-v2`, `operation-receipt-v1`, `operation-status-v1`, and
`runtime-snapshot-v1`—all reachable by wrapping the existing lab provisioning
code. Issue #311 promoted APTL to `orchestration-capable`: the manifest
declared a real `capabilities.orchestrator` and the
`workflow-result-envelope-v1` / `workflow-history-event-stream-v1` contracts,
the runtime target published a concrete ACES `Orchestrator`
(`aptl.backends.aces_orchestrator`), and scenario start routed through the ACES
control plane. Issue #312 then promoted the evaluator surface through
`aptl.backends.aces_evaluator` and the evaluation result/history contracts.

Current code may advance beyond those historical milestones. The canonical
profile claim is whatever `create_aptl_manifest()` plus the static/live gates
validate today; as of this update those paths target
`full-remote-control-plane`. Cleanup work must not preserve older
`provisioning-only`, `orchestration-capable`, or `orchestration-evaluation`
wording as a current contract unless it is clearly labeled historical.

## Parity Gate

Before cutover, the ACES TechVault scenario had to reach capability parity
with the union of the legacy scenario set now archived under
`scenarios/archive/`. Concretely it had to exercise:

- the same node / service / vulnerability / feature surfaces
- the same injects and scenario flow shapes
- the same objectives and scoring outputs (where SCN-007 applies)
- the same run-archive surfaces captured for current scenarios

The parity check was reviewed in the cutover PR description as a hard
prerequisite. Post-cutover cleanup continues to preserve the inventory as the
audit surface.

## Parity Inventory Boundary

Issue #318's parity inventory is the authoritative review surface for
deciding whether the ACES TechVault can replace the legacy scenario set. It
is not a runtime schema, not a new SDL, and not a deployment authority.

The inventory lived at `docs/aces/parity-inventory.yaml` with a
human-readable overview at `docs/aces/parity-inventory.md`. Its schema
was enforced by `tests/test_parity_inventory.py`. (Both files and that test
were removed; see the 2026-07-12 status update above.)

The inventory must map every legacy surface to exactly one owning category:

- **ACES SDL** when the authored scenario can express the surface directly
  through the ACES parser, schemas, semantic validators, and compiled
  `RuntimeModel`.
- **ACES schema/profile gap** when the concept belongs in ACES rather than
  APTL; these rows must cite an ACES follow-up instead of adding an APTL
  extension that recreates the retired in-tree SDL.
- **APTL backend responsibility** when the concept is backend realization
  detail: Docker Compose profiles, generated runtime config, lab-managed TLS,
  SOC seed material, deployment inventory, readiness classification, snapshots,
  run archive persistence, or host/container interaction.
- **Validation gate** when the surface is not authored but must be proven by
  conformance, static parity tests, live lab validation, snapshots, or run
  archive assertions.
- **Cutover-only archive/cleanup** when the legacy field is retained only as
  reference material after the Phase B move to `scenarios/archive/`.

The canonical source for a row is the existing owner, not the inventory
document itself. In particular:

- authored legacy fields now come from archived reference fixtures under
  `scenarios/archive/`;
- topology, profiles, networks, static IPs, hostnames, volumes, health checks,
  published ports, and service dependencies come from `docker-compose.yml` and
  the `DeploymentBackend` inventory methods;
- durable first-party knobs come from `AptlConfig`, not ad hoc YAML keys;
- `.env` values and generated secret-bearing config come from `EnvVars`,
  `find_placeholder_env_values`, ADR-028, ADR-029, and ADR-034;
- lab lifecycle and readiness surfaces come from `_LAB_START_STEPS`,
  `LabResult`, `StartupOutcome`, and `StartupDiagnostic`;
- runtime snapshots come from `RangeSnapshot.to_dict()` and the endpoint
  registry boundary in ADR-036;
- run archives come from `LocalRunStore` and its redacting JSON/JSONL write
  boundary.

The inventory may be human-readable or machine-readable, but if it becomes
machine-readable it must stay a narrow audit manifest: stable legacy
identifier, canonical source, owning category, ACES/runtime/backend target,
validation evidence, and blocking follow-up. It must not introduce a second
Pydantic `ScenarioDefinition`, a second ACES model, a duplicate Docker Compose
parser, a duplicate secret taxonomy, a duplicate readiness taxonomy, or a
parallel exception/result envelope.

## ACES Backend Integration Guardrails

APTL's ACES backend target is an adapter over existing APTL control-plane
boundaries. The implementation must not bypass those boundaries just because
the caller is ACES.

- ACES SDL documents enter through the ACES reference parser and semantic
  validators; APTL does not perform structural revalidation of ACES SDL with
  local models.
- ACES runtime work enters APTL through the ACES `RuntimeModel`,
  `ExecutionPlan`, backend manifest, operation receipt/status, and runtime
  snapshot contracts. The APTL-side target adapts those contracts to existing
  APTL owners rather than inventing a parallel runtime manager.
- Docker, container, and host inventory operations continue through
  `DeploymentBackend`; no ACES adapter code should call raw Docker or parse
  Compose output directly.
- Lab start/stop behavior continues to produce `LabResult` and structured
  startup diagnostics at APTL-facing edges. ACES-facing failures are translated
  into ACES diagnostics or operation-status envelopes at the adapter boundary;
  do not add an `AcesAptlError` hierarchy or expose raw backend exception text.
- Generated config, SOC TLS material, seed outputs, and any other
  secret-bearing runtime artifacts remain under the ADR-028 / ADR-034 generated
  artifact model. The backend manifest and parity inventory must not embed
  `.env` values, private key material, API tokens, cookies, or rendered config.
- Snapshot, status, telemetry, CLI/API output, run archives, and conformance
  artifacts remain subject to ADR-029 redaction. New ACES status or run
  evidence writers must reuse `RangeSnapshot.to_dict()` and `LocalRunStore`
  JSON/JSONL redaction boundaries where those artifacts cross APTL
  serialization.
- Published backend capability stays profile-named and contract-validated:
  `create_aptl_manifest()` plus the static/live conformance gates define the
  current claim. Any future profile promotion must update the manifest,
  runtime target components, conformance gates, and ADR wording together.

The extensibility seam is the ACES backend capability profile plus a small
backend realization map from ACES runtime resource kinds to existing APTL
control-plane owners. Do not make TechVault-specific branches the public
adapter contract; TechVault is the parity proving case for the supported
expressivity class, not the backend's type system.

## Legacy Cleanup Reconciliation

Issue #530 is a post-cutover reconciliation, not a new scenario-authoring
surface. It must leave one active path:

- Public runtime selection flows through `scenarios/catalog.json`,
  `aptl.core.scenario_catalog.resolve_scenario_selection()`,
  `aces_sdl.parse_sdl_file`, `RuntimeManager.plan()`, and
  `aptl.backends.aces.start_aces_scenario()`.
- Backend capability and runtime handoff flow through `create_aptl_manifest()`,
  `create_aptl_runtime_target()`, `AptlProvisioner`, `AptlOrchestrator`,
  `AptlEvaluator`, `AptlParticipantRuntime`, ACES diagnostics, and
  `DeploymentBackend`.
- Legacy `scenarios/*.yaml`, `aptl.core.sdl`, `aptl.core.scenarios`, and
  `ScenarioDefinition` references may remain only when explicitly marked as
  historical or reference-only and unreachable from catalog/default startup,
  static/live gates, and runtime loaders. Unlabeled references are drift.
- If any legacy local SDL code is intentionally retained, this ADR and Ground
  Control status must say why. It must not parse, validate, or model ACES SDL,
  and it must not reintroduce APTL-local SDL semantics as a source of truth.
- The parity inventory and historical preflight notes remain audit/history
  surfaces. They must not become runtime inputs, alternate schema authorities,
  or justification for keeping duplicate parser, validator, exception, or
  readiness layers alive.
- The cleanup regression target is that
  `rg "aptl.core.sdl|ScenarioDefinition|scenarios/.*\\.yaml" docs src tests scenarios`
  returns either no hits or only hits carrying clear historical/reference-only
  labels.

## Historical Migration Plan

The migration split into a multi-PR prep phase and a single-PR cutover. This
section records the original adoption sequence; current cleanup work is governed
by the Legacy Cleanup Reconciliation section above.

### Phase A—Prep (multiple PRs, parallel ACES path, non-default)

1. Add `aces-sdl` as an APTL Python dependency.
2. Implement an ACES `RuntimeTarget` against the existing lab
   orchestration. Land it as a *parallel* path; existing CLI entrypoints
   continue to use `aptl.core.sdl`.
3. Publish APTL's `backend-manifest-v2` under an APTL-side contracts
   path.
4. Wire `aces conformance backend --profile orchestration-capable` as an
   **advisory** check (non-blocking) so drift is visible during Phase A.
5. Author `scenarios/techvault.sdl.yaml` in ACES SDL.

### Parity Gate

See dedicated section above. Hard prerequisite to Phase B.

### Phase B—Cutover (single PR)

Lands in one PR:

- Default public startup scenario flips to
  `scenarios/techvault-operational.sdl.yaml`; the detailed
  `scenarios/techvault.sdl.yaml` remains the inventory/parity evidence
  artifact.
- `aptl lab` and CLI entrypoints route through ACES `RuntimeManager`.
- `scenarios/*.yaml` moves to `scenarios/archive/` with a README marking
  the directory strictly reference-only (not loaded by any runtime path).
- `aptl.core.sdl` deleted.
- `aptl.core.scenarios` Pydantic models deleted; the module remains only for
  shared session/continuity exception types.
- `aces conformance backend --profile orchestration-capable` switches from
  advisory to enforced (pre-push gate).
- GRC workflow platform reconciliation in the same PR:
  - DSL-001 → DEPRECATED
  - SCN-001 → DEPRECATED
  - DSL-002..DSL-009 → DEPRECATED (no per-item cross-links)
  - RTE-001 statement updated to consume the ACES `RuntimeModel`
  - Follow-on issues #311 and #312 confirmed open and linked

SCN-010 itself is ACTIVE from creation; the cutover does not flip its
status.
- Existing traceability links from the deprecated requirements are
  preserved as historical record; new links from SCN-010 are created
  during the same PR.

The cutover PR is large by necessity and will not be split. Splitting
would leave APTL with a half-flipped default surface or inconsistent
deprecations across releases.

## Consequences

### Positive

- Cross-backend reproducibility becomes demonstrable: the same ACES SDL
  document can run on APTL's lab and on any other conforming backend.
- DSL-001 and DSL-002..DSL-009 fold into the ACES roadmap; APTL stops
  paying duplicate grammar/parser/validation/tooling costs.
- APTL gains ACES's existing tooling (`resolve`, `verify-imports`,
  `publish`, lockfiles, OCI module distribution, MCP server) for free.
- ACES gains its first real-world conformant backend—the research
  story.
- Run provenance gains typed clock/synchronization/pacing surfaces from
  ACES contracts, supporting reproducibility across realizations.

### Negative / costs

- Migration cost for existing scenarios—but they move to archive, not
  being rewritten, so this is a small one-time move once the ACES
  TechVault reaches parity.
- APTL now depends on the `aces-sdl` Python package; version pinning and
  upstream-coordination become real workflow concerns.
- Backend conformance becomes a pre-push gate; failing conformance
  blocks merge. This is the intended quality contract.
- DSL-001 / SCN-001 deprecation cascades through the GRC workflow platform
  traceability—every link from those requirements must be reconciled
  in the cutover PR.

## Alternatives Considered

1. **Keep APTL's in-tree SDL, mirror ACES grammar.** Rejected: defeats
   the cross-backend reproducibility goal; APTL becomes an ACES dialect
   fork that has to stay in sync manually, with no machine-readable
   conformance signal.
2. **Adopt ACES SDL but skip the backend conformance suite.** Rejected:
   without conformance, APTL is not a demonstrable ACES backend, and the
   research claim collapses to "we use ACES syntax," not "ACES portability
   holds against a real range".
3. **Defer adoption until ACES reaches 1.0.** Rejected: ACES needs APTL
   as a real backend to drive contract design (`backend-manifest-v2`,
   profile splits, evaluator contracts already reflect that). Delaying
   makes both projects harder; co-evolution is the design assumption.

## Related Requirements

- Supersedes: DSL-001 (Formal Scenario Specification Language),
  SCN-001 (Declarative YAML Scenario Specifications)—both transitioned
  to DEPRECATED at cutover
- Deprecates at cutover: DSL-002 through DSL-009—no per-item
  cross-links; bulk DEPRECATED transition
- Updates at cutover: RTE-001 (Scenario Runtime Engine)—input source
  changes to ACES `RuntimeModel`
- Implements: SCN-010 (ACES SDL as APTL's Canonical Scenario Authoring
  Surface)

## Related Issues

- Parent: [#310](https://github.com/Brad-Edwards/aptl/issues/310)—
  Adopt ACES SDL as APTL's canonical scenario authoring surface
- Follow-on: [#311](https://github.com/Brad-Edwards/aptl/issues/311)—
  Upgrade APTL backend conformance to `orchestration-capable` profile
- Follow-on: [#312](https://github.com/Brad-Edwards/aptl/issues/312)—
  Upgrade APTL backend conformance to `orchestration-evaluation` profile
