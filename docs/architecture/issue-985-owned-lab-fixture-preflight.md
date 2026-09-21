# Issue #985 Owned Lab Fixture Preflight

This is architecture guidance, not an implementation plan. The issue is the
contract; no Ground Control requirement is attached. Existing decisions in
[the #969 preflight](issue-969-platform-safety-gates-preflight.md),
[the #993 preflight](issue-993-boot-realization-regressions-preflight.md), and
[boot coverage](../testing/boot-realization-coverage.md) remain authoritative.
No new ADR or product abstraction is needed.

## Ownership And Admission

Prefer a checked-in, small pack under `tests/fixtures/`, with an identity distinct
from TechVault. **Location/publication remains an explicit implementation
decision:** record the selected directory and why repository ownership suffices
in the fixture's maintenance note. A separate publication needs an actual
external consumer and a concrete reason. Neither a fixture distribution nor a
fixture framework is currently justified. The test tree must retain the valid
fixture required by the issue even if a later consumer motivates publication.

Use `aptl.core.scenario_bundle.env_pack_bundle(staging_root, identity,
source_pack=...)`. It already stages independent copies and calls env-packs'
`validate_pack` and `validate_pack_content_manifest`. `ScenarioBundle` and
`PackIdentity` are the existing handoff and identity models. Use env-packs' public
format/content tooling for the pack layout and associated-artifact manifest;
do not copy its schema, digest algorithm, or validators into test helpers.
Pack directory, declared identity, and `sdl/<identity>.sdl.yaml` must agree.
Keep maintenance prose outside the inventory unless the pack format includes it.

Maintain one canonical SDL containing the existing
`materialization-envelope.sdl.yaml` behavior. If it moves into the pack, update
its consumers and documentation together; do not retain two editable copies or
a symlink masquerading as a manifest member. The pack identity, SDL display
name, node address, backend profile, and Docker project identity are separate
concepts. Renaming the pack does not require renaming the existing smoke node.

There is an important public-interface limit: `ScenarioSourceConfig` has no
`source_pack` field, and `_raes_scenario_resolution.resolve_scenario_bundle()`
selects installed-package resources for `source="env-pack"`. `scenario.root`
does not override that acquisition. An explicit CLI `--scenario-path` selects a
**project-tree** bundle, even when its bytes came from a validated pack.
Retain the installed-wheel CLI smoke's explicit-path route using the canonical
fixture SDL, and prove actual pack admission/realization separately through
the existing resolver. Do not describe that CLI run as pack-identity coverage.
A requirement to carry local-pack identity through the public CLI would need a
real source-selection design; it must not be smuggled in as a fixture flag,
site-packages mutation, `PYTHONPATH` override, or fabricated bundle receipt.

## Size And Test Boundaries

#993 is already present in this checkout. Preserve its single causal chain:
package installation, local user/group and directory realization, inline
non-secret SSH configuration, enabled/active package-owned service, listener on
the configured port, exact loopback host publication and a real connection,
plus an end-only workflow with terminal RAES state and history. Reuse
`scripts/ci/assert_boot_realization.py` and its `BootExpectation`; retain its
negative tests in `tests/test_boot_realization_gate.py`.

Add only small associated file/archive bytes needed by migrated generic
pack-content and digest/readback cases. These need not become extra live nodes
or services. Preserve #993's inline-content causal test rather than replacing it
with an unrelated artifact lookup. One-node live coverage does not satisfy the
live-gate variation check's two-distinct-node premise: use a bounded test-local
variation through the existing RAES models, not a second permanent live pack.

Separate cases by the behavior they prove, not by filename or the presence of
the word TechVault:

- Generic staging, containment, concurrent isolation, restaging, content
  resolution and satisfaction cases in `test_env_pack_bundle.py`,
  `test_pack_content_resolution.py`, `test_raes_content_satisfaction.py`, and
  `test_scenario_bundle.py` can use owned bytes. Preserve invalid manifest,
  digest mismatch, missing realization and rejected-source assertions.
- Generic lifecycle, readiness, archive and failure cases in
  `test_techvault_live_gate.py` can use the fixture. Existing narrowly constructed
  RAES plans/DTOs in lifecycle and realization unit tests remain useful; do not
  replace every unit input with a pack admission or expand the fixture to match
  every mocked graph. Mock Docker/transport effects where appropriate, not the
  validators whose passage the fixture is meant to prove.
- Keep released evidence contracts, exact pack digest/version checks,
  `test_plugin_pack_compatibility.py` (#879), TechVault realization/attestation,
  static/live gates, and provider-specific checks on the real released pack.
  Do not derive their expected identity from a provider's own claim, loosen
  pins, skip missing plugins, or silently remove CI selection of those tests.

`tests/helpers.py` is currently unsuitable as the generic fixture loader: its
module initialization loads project `.env` and may invoke the TheHive API-key
script. Keep the loader small and import-safe, using pytest temporary paths and
the production resolver, without importing that helper module. Replace the
live-gate module's collection-time `mkdtemp`/TechVault staging with scoped pytest
fixtures for migrated cases. Never mutate a shared admitted tree, regenerate a
manifest automatically to bless corruption, or write test output into pack bytes.

## Cross-Cutting Passage

| Layer and canonical incumbent | Required passage |
| --- | --- |
| Acquisition and content identity: `scenario_bundle.py`, env-packs validators and `resolve_pack_artifact` | Validate real staged bytes and exact inventory, then retain the admitted identity through pack-backed realization. Use isolated singly linked copies and `ScenarioBundle.read_asset()`/`read_contained_nofollow()` for contained reads. Do not infer source-tree symlink rejection from staging: current `copytree` dereferences source links; committed fixture members must be ordinary files. Tests of source acquisition versus staged validation must identify which boundary they exercise. |
| Config and selection: strict `AptlConfig`, `ScenarioSourceConfig`, `scenario_catalog.py` | Use supported fields and normal selector precedence. Do not add a fixture schema or misuse `root`. Use a simple fixed safe pack ID; current scenario identity validation trims/checks emptiness, so it is not a general path-safety gate for newly exposed arbitrary source input. |
| RAES admission and deployment: parser/compiler/planner, `create_aptl_manifest()`, `AptlProvisioner`, `DeploymentRealizationSpec`, realization envelope | Admit the same scenario contract and require actual observation/satisfaction. No manually assembled successful admission, fixture-only capability, or permissive backend branch. Preserve SEM-218 failures; service and filesystem declarations must stay within the observable dimensions documented in boot coverage. |
| Optional providers: `scenario_startup.py`, `pack_interaction_discovery.py`, runtime-parameter discovery | Use exact identity selection and existing absent-startup/unprofiled-serving behavior. A new fixture identity must not load TechVault hooks or borrow its profiles. Do not install a no-op adapter merely to start a generic pack. |
| Semantic verification: `scenario_verification.py`, existing discovery/runner, `_live_gate_models.py` | Operational machinery and semantic qualification are distinct. Missing semantic verifier remains `BLOCKED`, never a pass. Unit seam tests may supply a narrow fake provider via existing discovery; the fixture needs no published semantic plugin. Retain `VerificationReport`, `QualifiedTarget` and their atomic compatibility checks. |
| Auth and secret/env binding: ADR-029, `EnvVars`/`hydrate_dotenv()`, `ScenarioStartupPlan` validators | The fixture declares no credentials, hooks or env bindings. Do not import ambient live-lab credentials or pass the host environment into fixture scripts. If a focused case exercises aliases/container bindings, use the existing typed fields, name/uniqueness validators and Docker transport-key restrictions. Local CLI smoke adds no API/MCP route and must not weaken token, Host, CSRF, session or participant authorization. |
| Content and OS execution: `raes_content_source_policy.py`, materializer engine, `DockerMaterializationExecutor`, contained/atomic writers | Keep forbidden-source policy independent of `sensitive: false`; use existing stdin/file delivery and digest readback. No shell interpolation of SDL, secret in argv/URLs, arbitrary seed script, host mount or socket. The verifier's existing `--content-text` is exclusively public non-secret expectation data; never generalize it into credential delivery. |
| Runtime containment: generic systemd substrate, port validators/readback, `WorkspaceOwnership`, lifecycle guard | Reuse the packaged substrate and bounded init privileges. No fixture-authored privileged mode or `runtime.orchestration_authorities`. Container wildcard listening is distinct from host exposure: require exact loopback host binding. Select exactly one container by effective durable project identity plus `aptl.node.address`, not its display name or image. Retain bounded deadlines and isolate concurrent runs; fixed host port/subnet require a dedicated runner or non-conflicting test-local allocation. |
| Errors, observability and persistence: `EnvPackError`, RAES `Diagnostic`, `LabResult`, `get_logger()`, `redact()`, `LocalRunStore` | Preserve typed failures, blocked/failed/passed distinctions, safe diagnostics and existing run-store containment/redaction. Parse persisted workflow state using RAES `WorkflowExecutionState`. Do not dump raw exception payloads, subprocess output, environment, inspect documents or archives; add no log/result/exception hierarchy or persistence store. |
| Installed assets, CI and cleanup: `hatch_build.py`, `_asset_manifest.py`, `assets.materialize()`, Checks workflow, teardown verifier | Keep the fixture test-owned, outside shipped asset roots. Build/install with locked tools/dependencies and run the installed CLI from an empty materialized project. Copy only explicit test inputs; no checkout code or missing production assets. Keep the existing boot job/context and both `always()` cleanup steps. `observe_project_runtime()` and `project_scoped_volume_names()` must prove absence of stopped containers, networks and volumes; query failure is failure, never daemon-wide prune. |

## Extensibility, Repository Scope And Non-Goals

The seam already exists: explicit source directory, identity and caller-owned
staging root yield a validated `ScenarioBundle`. Small test helpers should pass
these values through, not become a pack builder/registry. The verifier already
accepts node/workflow addresses, content expectation and port tuple; keep those
parameters independent of TechVault or the fixture's directory name. A future
regression can add one small declaration and effect assertion without editing
the resolver or adding another CI job.

In addition to the owners above, coordinated consumers are
`test_lab_fresh_start.py`, `test_imagefree_admission_integration.py`,
`test_scenarios.py`, `test_platform_ci_gates.py`, boot-coverage documentation,
the #969/#993 notes, and the existing compatibility suites. Build and host
surfaces include `pyproject.toml`, `uv.lock`, hashed requirements, asset roots,
`containers/base`, Docker/Compose, temporary projects and ownership/run files.
These are inspection boundaries, not a mandate to edit them. Keep dependencies
on RAES/env-packs validators: independence from TechVault bytes does not mean
independence from their released contract libraries.

Use `.ground-control.yaml`, `.gc/plan-rules.md`, pre-commit and existing pytest/CI
conventions. Preserve live opt-in gating and separately selected compatibility
checks; verify collection itself no longer acquires TechVault for migrated
generic modules. New fixture bytes must pass validation after formatting, since
formatting can change their manifest digests. A Compose/config/Dockerfile change
would trigger clean-machine lab validation and is not justified for convenience.

Non-goals are implementing #970's lifecycle redesign, publishing a pack, adding
local-pack CLI acquisition, removing packaged TechVault adapters/dependencies,
changing auth or schemas, creating a fixture framework, widening #993 into all
realization concerns (#1126), or claiming full TechVault, participant, remote
Docker, cross-platform or offline qualification. This preflight changes guidance
only; fixture creation, test migration and runtime validation belong to #985's
implementation.
