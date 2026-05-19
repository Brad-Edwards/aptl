---
date: 2026-05-19
side: both
sibling_entry:
follow_ups:
  - Brad-Edwards/aptl#310 — wire `AptlProvisioner.apply()` through `aptl.core.lab.orchestrate_lab_start` + `aptl.core.deployment.DeploymentBackend`, returning `ApplyResult(success=False, diagnostics=[...])` instead of raising
  - Brad-Edwards/aces — open an issue tracking the `provisioner-node-types` vocabulary review (no `container` term; APTL containerized labs model as `vm`)
adr_impact:
  - ADR-035 — amended with a User-Visible Invariance section spelling out the parity contract (pre-/post-cutover indistinguishable from a user's perspective)
contract_impact:
  - backend-manifest-v2 — APTL's manifest factory exercises the
    `concept_bindings` + `realization_support` requirements end-to-end
    for the first time outside `aces_backend_stubs`
profile_impact:
  - provisioning-only
---

## Context

#310 / SCN-010 / ADR-035 adopt ACES SDL as APTL's canonical scenario
authoring surface. This PR (#316) is the full implementation —
foundational scaffolding, real `apply()` wiring, TechVault scenario
authoring, parity-gate verification, and the legacy-SDL cutover all
land here as separate commits on one branch. The user's parity bar:
**someone using APTL pre- and post-cutover must not be able to tell
the difference from the stack's behavior.** Every test in
`tests/test_range_integration.py` that passes on the legacy path must
pass on the ACES path; `aptl` CLI surface unchanged; lab orchestration
unchanged.

This entry captures findings from the first integration probes
(scaffolding + end-to-end smoke test) that landed on the branch.

## What we expected

The ACES reference backend (`aces_backend_stubs`) made the manifest
look like the central declaration with a few helper fields. Plug in
APTL's identity, declare `provisioning-only`, return an empty
diagnostic list from `validate()`, and the conformance suite should
go green.

## What we found

Three contract-surface frictions surfaced during the scaffolding:

1. **`BackendManifest` requires `realization_support` AND
   `concept_bindings`.** Both must be non-empty for the manifest to
   construct; the constructor raises `ValueError` if either is
   missing. The reference stub (`aces_backend_stubs/stubs.py`)
   declares the full vocabulary, but the *minimum* shape needed to
   pass `provisioning-only` conformance isn't documented anywhere we
   could find — we cribbed from the stub.
2. **The controlled-vocabulary `provisioner-node-types` permits only
   `{vm, switch}`.** APTL's containerized lab hosts (Wazuh manager,
   Kali, victim, workstation) model most naturally as `container`,
   which isn't in the vocabulary. We declared `vm` to satisfy the
   closed-world validator. The lab IS effectively VM-like from a
   scenario perspective, but this is the first case where a real
   backend has to map its node taxonomy onto ACES's intentionally
   narrow controlled vocabulary. Worth a vocabulary review.
3. **The `Provisioner` `Protocol` is not `@runtime_checkable`.**
   `isinstance(obj, Provisioner)` raises `TypeError` rather than
   doing structural shape-checking. Tests that want to verify a
   target's provisioner conforms have to duck-type against
   `validate` and `apply` directly. The reference stub uses concrete
   classes so this doesn't bite it; downstream backend authors will
   trip on the same wall the first time they try to assert
   conformance in tests.
4. **`aces_contracts` cannot find its controlled-vocabulary catalog
   under a non-editable install — and pip's interaction with
   direct-reference dependencies makes "just install editably"
   non-trivial.** `_repo_root()` is defined as
   `Path(__file__).resolve().parents[4]` and the catalog at
   `contracts/concept-authority/controlled-vocabularies-v1.json` is
   expected to live there. This assumes the source-tree layout
   `<repo>/implementations/python/packages/aces_contracts/__init__.py`,
   which only matches when aces-sdl is installed editably from the
   actual source tree. A wheel install lands the package under
   `site-packages/aces_contracts/` and `parents[4]` points at the
   venv root or higher — the catalog file isn't found, every
   `BackendManifest` construction call dies with `FileNotFoundError`.

   We hit three layered variants of this:

   - **Variant A — transitive wheel install.** APTL's CI initially
     declared aces-sdl in `[project].dependencies` as a `name @
     git+...` direct reference, then ran `pip install -e ".[dev]"`.
     Pip built aces-sdl as a wheel and installed it into
     site-packages; the path walk failed.
   - **Variant B — `pip install -e "git+...#subdirectory=..."` is
     not editable on GitHub Actions.** Even with the explicit `-e`
     flag, pip builds a wheel from the subdirectory and installs
     to site-packages.
   - **Variant C — extras with direct-ref deps re-install over
     existing editable installs.** We tried installing aces-sdl
     editably first via `pip install -e "git+..."` (which DID land
     editably in some configurations) and THEN running `pip install
     -e ".[aces]"`. Pip's resolution of the `[aces]` extra's
     `aces-sdl @ git+...` line re-installed aces-sdl from the URL as
     a wheel, OVERWRITING the editable install. The first install
     was fine; the second invocation silently invalidated it.

   **Resolution we shipped.** Drop the dependency declaration
   entirely from APTL's pyproject — neither core nor extra. CI and
   developers clone aces-sdl with `git clone` to `../aces-sdl`,
   checkout the pinned SHA, then `pip install -e
   ../aces-sdl/implementations/python` BEFORE installing APTL.
   `aptl.backends.aces` imports succeed; tests using
   `pytest.importorskip("aces_backend_protocols.protocols")` skip
   gracefully when aces-sdl is absent. The pinned SHA lives in the
   GitHub workflow + this lessons entry rather than in
   pyproject.toml, but the trade-off is worth it: pyproject's
   declarative dependency model fights us as long as aces-sdl
   carries source-tree-relative resource lookups.

   **Real fix on the ACES side.** Package the `contracts/` tree as
   installable data files (PEP 561-style `package_data` /
   `tool.hatch.build.targets.wheel.shared-data`) and load via
   `importlib.resources`. With that, every install mode works and
   APTL can declare aces-sdl as a normal pyproject dependency.

## Decision

- **fix-in-aptl** for #1 and #3: APTL's manifest factory declares
  both `realization_support` and `concept_bindings` blocks shaped
  after the reference stub, and the test suite duck-types instead of
  using `isinstance`. These are downstream adaptations to upstream
  contract shapes; the right home is the backend.
- **cross-repo-coordination** for #2: APTL declares `vm` for now and
  files a follow-up on the ACES side proposing either adding
  `container` to the `provisioner-node-types` vocabulary or
  documenting the mapping guidance for backends that surface
  container-shaped node taxonomies. APTL doesn't need it changed
  before Phase A.2 lands; the `vm` declaration is honest if
  imprecise.
- **fix-in-aces** for #1's documentation gap (separately surfaced in
  the ACES-side entry once it lands): the
  `aces_backend_protocols.capabilities.BackendManifest` docstring
  should call out that `concept_bindings` and `realization_support`
  are required non-empty, and the smallest acceptable shape for a
  `provisioning-only` backend should appear next to the profile JSON
  in `contracts/profiles/backend/provisioning-only.json`.

## Why this side

The vocabulary question (#2) is a contract decision — ACES owns the
controlled vocabulary, so the proposal belongs there. The manifest
documentation gap (#1) is upstream's to fix; APTL's adapter just
documents the gotcha in code comments meanwhile. The duck-typing
adjustment (#3) is APTL's to live with until ACES decides whether to
mark the protocols `@runtime_checkable` (which would couple ACES's
protocol surface to its consumers in a way that may not be intended;
arguably the duck-type-in-tests pattern is fine).

## Dead-code audit (the "legacy SDL" reality)

The migration framing in #310 / ADR-035 implies replacing a live
in-tree SDL with ACES. The codebase audit shows otherwise:

- **`aptl.core.sdl/` (the in-tree SDL package, 20+ modules)** —
  parsing/validation/contracts code, used only by its own tests.
  No active CLI path reaches it.
- **`aptl.core.scenarios.load_scenario`** — wraps
  `aptl.core.sdl.parse_sdl`. Called only by `tests/test_scenarios.py`
  and `tests/test_scenario_contracts.py`. No user-facing CLI command
  invokes it.
- **`aptl.core.runtime/`** — mirror of ACES's runtime model
  (capabilities, manager, models, planner, registry). Used only by
  `tests/test_runtime_manager.py`. No active code path.
- **`src/aptl/backends/stubs.py`** — stub Provisioner/Orchestrator
  /Evaluator wired against `aptl.core.runtime`'s in-tree mirror. Used
  only by runtime tests.
- **`scenarios/*.yaml` files (6 files, 1575 lines)** — authored with a
  Pydantic-style schema (`metadata`/`mode`/`containers`/`objectives`/etc.)
  but NO loader code anywhere in `src/aptl/` parses them. The Pydantic
  `ScenarioDefinition` referenced in #310's body and ADR-035 (SCN-001
  / DSL-001..DSL-009) does not exist as importable code today.
- **`aptl scenario` CLI** — referenced by
  `tests/test_range_integration.py::TestScenarioHarness` but the
  Typer subcommand does not exist. Running
  `APTL_SMOKE=1 pytest tests/test_range_integration.py::TestScenarioHarness`
  fails today with "No such command 'scenario'".

**What this means for the parity bar.** "User-visible behavior
indistinguishable pre- and post-cutover" is easier than #310's framing
suggests: nothing user-facing currently flows through SDL, so the
cutover doesn't change anything users touch. The actual work:

- Add real `aptl scenario start/stop/list` CLI commands (NEW
  functionality, not a migration). Build them on the ACES path
  directly — there's no legacy CLI to be parity-compatible with.
- Author one or more ACES SDL scenarios (TechVault, plus the
  brute-force variant the integration test references) such that
  `aptl scenario start <name>` produces a working lab via the ACES
  RuntimeManager → AptlProvisioner → DeploymentBackend chain.
- Delete the dead-code surface listed above (~3000 lines of unused
  module code + their tests).
- Make `tests/test_range_integration.py::TestScenarioHarness::test_scenario_lifecycle_with_live_detection`
  actually pass (it fails today; success post-PR is a parity
  improvement, not regression).
- Flip the `aces-conformance` CI job from advisory to blocking.
- Update DSL-001 / SCN-001 / DSL-002..DSL-009 requirements per
  #310's reconciliation list (they're DRAFT today; transition to
  DEPRECATED via Ground Control as part of the cutover).

**The parity bar is now empirical, not aspirational.** Every test
that passes today must pass post-cutover. Tests that fail today
(like `aptl scenario` integration tests) are net new capability
when they go green; they don't constrain parity.

## Smoke probe findings (post-scaffolding)

Drove a minimal SDL document through ACES end-to-end against the
APTL target — `parse_sdl_file` → `compile_runtime_model` →
`RuntimeManager(target=create_aptl_target()).plan(scenario=sdl)` →
`manager.apply(plan)`. Captured three contract-shape findings that
shape Phase A.2 wiring:

5. **`RuntimeManager.apply()` catches backend exceptions and
   surfaces them as diagnostics, not propagated raises.** Our
   `AptlProvisioner.apply()` raises `ApplyNotImplementedError` for
   actionable plans; the manager catches it and returns
   `ApplyResult(success=False, diagnostics=[Diagnostic(code=
   'runtime.backend-call-failed', address='runtime.apply.provisioning',
   message='Backend method ... raised ApplyNotImplementedError: ...')])`.
   **Implication for real apply():** match the idiom. Catch our own
   errors *inside* `apply()` and return `ApplyResult(success=False,
   diagnostics=[...])` rather than raising. Same end-state from the
   manager's perspective but APTL controls the diagnostic shape
   (severity, code namespace, address resolution).
6. **Planner output is shape-stable across runs.** A minimal SDL with
   one `Switch` and one `VM` produces exactly two `ProvisionOp`
   entries: `CREATE provision.network.<switch-name>` and `CREATE
   provision.node.<vm-name>`. Resource types are `network` and
   `node`. APTL's apply path needs a translator from these
   address-prefixed resource types to Docker Compose primitives
   (networks → Docker networks, nodes → Docker Compose services).
   `provision.network.X` is one structural family; `provision.node.X`
   is another. The translator is the seam Phase A.2 builds.
7. **`RuntimeManager` is one-target.** Constructor takes a single
   `target=...` keyword; there's no registry-based selection at the
   manager level. `BackendRegistry` exists for "look up a backend by
   name" patterns (CLI flags, scenario manifest references), but the
   apply pipeline binds to one target at construction time. APTL's
   CLI will need to build the manager with the APTL target directly,
   not look it up via the registry.

## Follow-ups

- aptl#310 — wire `AptlProvisioner.apply()` through
  `DeploymentBackend` + `aptl.core.lab.orchestrate_lab_start`,
  returning `ApplyResult(success=False, diagnostics=[...])` for
  failures (don't raise — match ACES's idiom per finding 5 above).
- aces — vocabulary review issue (`provisioner-node-types`): add
  `container` term, or publish mapping guidance for container-shaped
  taxonomies.
- aces — manifest-construction documentation issue: document
  `realization_support` / `concept_bindings` minimums next to the
  profile JSONs.
- aces — `@runtime_checkable` decision on `aces_backend_protocols.protocols`
  (Provisioner / Orchestrator / Evaluator / ParticipantRuntime).
- aces — package the `contracts/` tree as installable package data
  (or use `importlib.resources`) so wheel installs work. The
  `parents[4]` source-tree-relative path walk is a real bug for any
  downstream that doesn't install aces-sdl editably (#310 Phase A.1
  hit it in APTL's CI before the editable-install workaround).
