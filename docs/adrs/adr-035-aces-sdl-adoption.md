# ADR-035: Adopt ACES SDL as APTL's Scenario Authoring Surface

## Status

accepted

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

## Integration Guardrails

The ACES backend is an adapter around APTL's existing control-plane
boundaries, not a replacement deployment stack inside APTL.

- Scenario authoring and semantic validation belong to ACES. APTL must
  not recreate ACES SDL models, validators, import resolution, lockfile
  handling, backend contract schemas, conformance profile logic, or
  operation/result envelope schemas.
- Durable APTL configuration remains `aptl.json` loaded through
  `aptl.core.config.load_config` / `AptlConfig`. Backend-specific knobs
  needed by the ACES adapter must enter through that strict first-party
  schema only when APTL owns them; ACES-owned contract payloads stay as
  ACES schemas and are validated by ACES tooling.
- Runtime secrets remain in `.env`, parsed by `load_dotenv`, shaped by
  `EnvVars`, and placeholder-checked by `find_placeholder_env_values`.
  The ACES adapter may consume typed environment state after the normal
  binding step, but must not parse `.env` itself or move secrets into
  `aptl.json`, manifests, SDL documents, logs, command lines, snapshots,
  or conformance output.
- Docker lifecycle, container interaction, host inventory, and SSH-remote
  transport stay behind `DeploymentBackend`. The ACES `RuntimeTarget`
  must call existing lab/deployment orchestration helpers or the backend
  protocol; it must not shell out to raw `docker`, `docker compose`, or
  SSH independently.
- User-facing lifecycle results continue to cross APTL edges as
  `LabResult`, `StartupOutcome`, `StartupDiagnostic`,
  `LabActionResponse`, and the existing CLI rendering. ACES diagnostics
  should be translated at the adapter boundary into these existing
  envelopes where they reach APTL CLI/API/web surfaces; do not add a
  second APTL exception hierarchy or readiness DTO.
- Snapshot and run-archive data remain owned by `RangeSnapshot.to_dict()`
  and `LocalRunStore`. New ACES-produced runtime or conformance artifacts
  that enter APTL run data must go through the same redaction/persistence
  boundary instead of relying on archive/export code to sanitize later.
- Logging uses `aptl.utils.logging.get_logger()`, and every diagnostic,
  exception string, persisted JSON/JSONL record, CLI/API payload, and
  trace-facing value remains subject to ADR-029 redaction. Process
  boundaries must not place bearer tokens, API keys, cookies, private
  keys, generated config contents, or credentialized curl bodies in
  argv; use existing safe helpers such as `curl_safe` for SOC HTTP
  subprocess access.

The intended extensibility seam is the ACES profile/backend manifest
plus a thin APTL adapter configuration boundary. Promotion from
`provisioning-only` to `orchestration-capable` or
`orchestration-evaluation` should update the declared ACES profile and
adapter capability mapping, not fork scenario loading, duplicate
contracts, or special-case TechVault in the control plane.

## Non-Goals and Anti-Patterns

- Do not implement an APTL dialect of ACES SDL or a compatibility
  translator from legacy `scenarios/*.yaml` into ACES as part of
  cutover. Legacy YAML is archived as reference material only.
- Do not keep `aptl.core.sdl` or Pydantic `ScenarioDefinition` alive as
  hidden fallback paths after Phase B. A dual default surface would
  invalidate the canonical-authoring decision.
- Do not infer runtime mode, backend profile, SOC/prime capability,
  objective support, or orchestration/evaluation support from filenames,
  scenario names, legacy fixture contents, or English diagnostics.
  Capability is declared in ACES contracts and APTL config/backend
  state, then validated by the planner/conformance gates.
- Do not add raw Docker, raw SSH, or raw subprocess command assembly in
  the ACES adapter when `DeploymentBackend` or existing lab helpers
  already own the operation.
- Do not introduce adapter-local secret taxonomies, redaction filters,
  config validators, manifest schemas, run-storage writers, or API
  response models beside the canonical APTL/ACES ones.

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

## Update (2026-05-19): User-Visible Invariance contract

Parity is not "the ACES contract surface is reachable and shape-correct"
— it is **user-visible behavior across the entire stack is identical
pre- and post-cutover**. The cutover lands the SDL replacement
underneath APTL; nobody using APTL should be able to tell the difference
from how the stack responds to their commands.

This makes the gate measurable rather than aspirational. The
following invariants are NON-NEGOTIABLE before cutover and are
the literal contract the cutover commit must meet:

1. **Every test in `tests/test_range_integration.py` that passes on
   the legacy path passes on the ACES path.** The full LIVE_LAB suite
   is the parity benchmark — not just the smoke subset. If a test
   relies on `scenarios/detect-brute-force.yaml`, the ACES-driven
   equivalent must produce the same observable outcomes (alerts
   indexed, scenario start/stop semantics, run archive contents,
   timing windows).
2. **`aptl` CLI surface unchanged.** Every command, flag, exit code,
   stdout/stderr shape, and config file path that APTL exposes today
   continues to work identically. `aptl lab start`, `aptl scenario
   start/stop/list`, `aptl runs`, all of it. The CLI does not learn
   about ACES; the cutover is an internal substitution.
3. **`aptl.json` schema unchanged in user-visible shape.** Internal
   knobs the adapter needs may land in the config, but the schema
   APTL has documented and shipped today must continue to validate
   every existing user config without rejection. No user has to
   edit their `aptl.json` to migrate.
4. **`LabResult` / `StartupOutcome` / `LabActionResponse` envelopes
   unchanged.** Web API consumers, CLI rendering, and persistence
   layers see the same shapes they see today. ACES `Diagnostic`
   entries translate into the existing envelopes at the adapter
   boundary; downstream code does not learn about ACES.
5. **Run archive shape unchanged.** `RangeSnapshot.to_dict()` and
   `LocalRunStore` produce JSON/JSONL bytes that match the existing
   structure. A diff of post-cutover archives against pre-cutover
   archives (with timestamps normalized) must show no semantic
   difference.
6. **Performance envelope unchanged.** Lab start/stop wall-clock
   times are within the existing performance envelope. No new
   per-scenario startup tax > 10%.
7. **Failure modes match.** When the legacy path raises
   `LabResult(success=False, error=...)`, the ACES path raises the
   same shape with the same error code class. Translation happens
   at the adapter boundary; user-facing error messages are
   indistinguishable in semantics.

The parity-gate pytest target (`tests/test_aces_parity.py`) is the
mechanical embodiment of this contract. It is `@pytest.mark.skip` until
the cutover PR is ready to merge; flipping the skip is what "meets
parity" literally means.

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
