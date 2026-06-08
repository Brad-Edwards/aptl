# ADR-035: Adopt ACES SDL as APTL's Scenario Authoring Surface

## Status

proposed

## Date

2026-05-18

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

APTL today maintains its own in-tree SDL at `aptl.core.sdl`, plus a
Pydantic-validated YAML schema at `aptl.core.scenarios` (SCN-001), with a
parallel grammar/parser/validation story tracked by DSL-001..DSL-009. The
in-tree SDL and ACES SDL both started from the Open Cyber Range SDL — the
same root — so the surfaces overlap substantially, and the in-tree fork is
already drifting in scope and naming.

Carrying two SDLs has three concrete costs:

1. **Cross-backend reproducibility — the central ACES claim — cannot be
   demonstrated using APTL scenarios** because their grammar is
   APTL-private. The research program cannot show "the same scenario ran
   on backend A and backend B" while APTL refuses to read the same
   document the other backends do.
2. **Every DSL-002..DSL-009 feature is duplicate work** against
   equivalent ACES features (variables/runtime substitution, composition,
   pre/post-conditions, CACAO/Attack Flow alignment, cleanup/rollback,
   topology declaration, user-behavior profiles).
3. **Tooling already exists in ACES** — `aces sdl resolve`,
   `aces sdl verify-imports`, `aces sdl publish`, lockfiles
   (`aces.lock.json`), OCI module distribution, MCP server, conformance
   runner — and would have to be rebuilt in-tree to reach parity.

## Decision

APTL adopts ACES SDL as its canonical scenario authoring surface and
implements an ACES backend target that wraps APTL's existing lab.

Specifically:

- Authored scenarios are ACES SDL documents parsed by `aces_sdl.parse_sdl`
  / `parse_sdl_file` against ACES's published schemas and semantic
  validators.
- APTL implements one `RuntimeTarget` registered into the ACES runtime
  target registry (final import path pinned during implementation) and
  publishes a `backend-manifest-v2` claiming conformance to the
  **`provisioning-only`** profile as the initial target. Promotion to
  `orchestration-capable` and `orchestration-evaluation` is tracked as
  follow-on GitHub issues (#311, #312) once the corresponding APTL
  capabilities (workflow execution under the orchestrator contract;
  objective evaluation under the evaluator contract) are wired through.
- APTL's CLI delegates `aptl lab start` and friends through the ACES
  `RuntimeManager` lifecycle (compile → plan → validate → apply → start
  orchestrator/evaluator → stop) instead of the current imperative Python
  lifecycle.
- APTL's published backend manifest is committed under an APTL-side
  contracts path (final location pinned during implementation) and
  validated by `aces conformance backend --profile provisioning-only` as
  a pre-push gate.
- The legacy `aptl.core.sdl` parser and `scenarios/*.yaml` Pydantic path
  remain functional throughout the adoption work. The `aces_sdl`
  dependency, the ACES backend target, and the ACES TechVault scenario
  land as a *parallel* path during Phase A.
- At cutover (Phase B, a single PR), the default scenario flips to the
  ACES-authored `techvault.sdl.yaml`, `scenarios/*.yaml` moves to
  `scenarios/archive/` as strictly reference-only material (not loaded by
  any runtime path), `aptl.core.sdl` is deleted, `aptl.core.scenarios`
  collapses to a thin loader around `aces_sdl.parse_sdl_file`, and
  Pydantic `ScenarioDefinition` models are deleted.

## Backend Profile Choice

APTL targets `provisioning-only` initially because that profile requires
only `backend-manifest-v2`, `operation-receipt-v1`, `operation-status-v1`,
and `runtime-snapshot-v1` — all reachable by wrapping the existing lab
provisioning code. Moving to `orchestration-capable` adds
`workflow-result-envelope-v1` and `workflow-history-event-stream-v1`,
which maps onto APTL's existing scenario runtime engine (RTE-001) but is
large enough to scope separately under issue #311.
`orchestration-evaluation` further adds the evaluator envelopes and
corresponds to SCN-007 (Objective-Based Scoring with Hints), tracked
under issue #312. The `full-remote-control-plane` profile is out of
scope.

## Parity Gate

Before cutover, the ACES TechVault scenario must reach capability parity
with the union of the current `scenarios/*.yaml` set. Concretely it must
exercise:

- the same node / service / vulnerability / feature surfaces
- the same injects and scenario flow shapes
- the same objectives and scoring outputs (where SCN-007 applies)
- the same run-archive surfaces captured for current scenarios

The parity check is reviewed in the cutover PR description and is a hard
prerequisite. No cutover PR merges without it.

## Parity Inventory Boundary

Issue #318's parity inventory is the authoritative review surface for
deciding whether the ACES TechVault can replace the legacy scenario set. It
is not a runtime schema, not a new SDL, and not a deployment authority.

The inventory lives at
[`docs/aces/parity-inventory.yaml`](../aces/parity-inventory.yaml) with a
human-readable overview at
[`docs/aces/parity-inventory.md`](../aces/parity-inventory.md). Its schema
is enforced by `tests/test_parity_inventory.py`.

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

- authored legacy fields come from `scenarios/*.yaml` until cutover;
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
  `provisioning-only` is the initial claim, and any profile promotion belongs
  to the follow-on issues already named here.

The extensibility seam is the ACES backend capability profile plus a small
backend realization map from ACES runtime resource kinds to existing APTL
control-plane owners. Do not make TechVault-specific branches the public
adapter contract; TechVault is the parity proving case for the supported
expressivity class, not the backend's type system.

## Migration Plan

The migration splits into a multi-PR prep phase and a single-PR cutover.
APTL remains fully functional throughout the prep phase — the legacy
in-tree SDL path stays the default until cutover.

### Phase A — Prep (multiple PRs, parallel ACES path, non-default)

1. Add `aces-sdl` as an APTL Python dependency.
2. Implement an ACES `RuntimeTarget` against the existing lab
   orchestration. Land it as a *parallel* path; existing CLI entrypoints
   continue to use `aptl.core.sdl`.
3. Publish APTL's `backend-manifest-v2` under an APTL-side contracts
   path.
4. Wire `aces conformance backend --profile provisioning-only` as an
   **advisory** check (non-blocking) so drift is visible during Phase A.
5. Author `scenarios/techvault.sdl.yaml` in ACES SDL.

### Parity Gate

See dedicated section above. Hard prerequisite to Phase B.

### Phase B — Cutover (single PR)

Lands in one PR:

- Default scenario flips to the ACES TechVault.
- `aptl lab` and CLI entrypoints route through ACES `RuntimeManager`.
- `scenarios/*.yaml` moves to `scenarios/archive/` with a README marking
  the directory strictly reference-only (not loaded by any runtime path).
- `aptl.core.sdl` deleted.
- `aptl.core.scenarios` Pydantic models deleted; loader collapses to a
  thin `aces_sdl.parse_sdl_file` wrapper.
- `aces conformance backend --profile provisioning-only` switches from
  advisory to enforced (pre-push gate).
- Ground Control reconciliation in the same PR:
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
- ACES gains its first real-world conformant backend — the research
  story.
- Run provenance gains typed clock/synchronization/pacing surfaces from
  ACES contracts, supporting reproducibility across realizations.

### Negative / costs

- Migration cost for existing scenarios — but they move to archive, not
  being rewritten, so this is a small one-time move once the ACES
  TechVault reaches parity.
- APTL now depends on the `aces-sdl` Python package; version pinning and
  upstream-coordination become real workflow concerns.
- Backend conformance becomes a pre-push gate; failing conformance
  blocks merge. This is the intended quality contract.
- DSL-001 / SCN-001 deprecation cascades through Ground Control
  traceability — every link from those requirements must be reconciled
  in the cutover PR.

## Alternatives Considered

1. **Keep APTL's in-tree SDL, mirror ACES grammar.** Rejected: defeats
   the cross-backend reproducibility goal; APTL becomes an ACES dialect
   fork that has to stay in sync manually, with no machine-readable
   conformance signal.
2. **Adopt ACES SDL but skip the backend conformance suite.** Rejected:
   without conformance, APTL is not a demonstrable ACES backend, and the
   research claim collapses to "we use ACES syntax", not "ACES portability
   holds against a real range".
3. **Defer adoption until ACES reaches 1.0.** Rejected: ACES needs APTL
   as a real backend to drive contract design (`backend-manifest-v2`,
   profile splits, evaluator contracts already reflect that). Delaying
   makes both projects harder; co-evolution is the design assumption.

## Related Requirements

- Supersedes: DSL-001 (Formal Scenario Specification Language),
  SCN-001 (Declarative YAML Scenario Specifications) — both transitioned
  to DEPRECATED at cutover
- Deprecates at cutover: DSL-002 through DSL-009 — no per-item
  cross-links; bulk DEPRECATED transition
- Updates at cutover: RTE-001 (Scenario Runtime Engine) — input source
  changes to ACES `RuntimeModel`
- Implements: SCN-010 (ACES SDL as APTL's Canonical Scenario Authoring
  Surface)

## Related Issues

- Parent: [#310](https://github.com/Brad-Edwards/aptl/issues/310) —
  Adopt ACES SDL as APTL's canonical scenario authoring surface
- Follow-on: [#311](https://github.com/Brad-Edwards/aptl/issues/311) —
  Upgrade APTL backend conformance to `orchestration-capable` profile
- Follow-on: [#312](https://github.com/Brad-Edwards/aptl/issues/312) —
  Upgrade APTL backend conformance to `orchestration-evaluation` profile
