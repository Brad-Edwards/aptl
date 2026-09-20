# Issue #970 Generic Lab Lifecycle Boundary Preflight

This note fixes the architecture boundary for decomposing lab startup. It is
guidance, not an implementation plan. At this preflight's baseline
(`4d55a949`), `src/aptl/core/lab.py` is 3,743 lines and has 25 ordered start
steps. It still combines generic lifecycle, RAES admission and apply, Wazuh and
SOC preparation, retry, scenario seeding, MCP setup, capture activation, range
snapshots and run records.

Issue #934 has already rejected a product-level “core plus experience” model.
APTL and LilRAE are one product across a rename; TechVault is a scenario pack.
For this issue, “experience startup hooks” therefore means behavior declared by
an admitted scenario pack or supplied by one content-qualified installed
extension. It does not create an experience object, package tier or second
product identity.

## Decisions And Ownership Boundaries

### One coordinator and one RAES route

`orchestrate_lab_start()` remains the public composition boundary. Its generic
coordinator owns the project lifecycle lock, fixed phase order, progress,
diagnostic accumulation, interruption propagation and the single final
projection to `LabResult`. `clean_boot_lab()`, lifecycle enforcement, CLI and
API remain callers of that same boundary.

The coordinator consumes one existing `AdmittedScenarioStart` and its
`AdmittedStartSurface` projection. It never parses, plans or interprets a
scenario itself. `aptl.backends.raes` remains the only adapter surface that
constructs the RAES runtime target, invokes the public RAES planning adapter,
and routes `RuntimeManager.apply()`. The temporary `AptlRuntimeManager` compatibility
subclass may remain while its upstream gaps are release-scoped, but it must not
become a second lifecycle runner. `core.runtime.WorkflowEngine` continues to
execute authored RAES workflows inside the RAES orchestrator; lab startup must
not be modeled as another RAES workflow or taught to use that engine.

`DeploymentBackend` remains the sole deployment authority. Generic lifecycle,
extensions, CLI and API do not run Docker or Compose independently. The direct
`docker info` appliance check, local-only assumptions and any touched raw
container command in `lab.py` must move behind an existing or narrow typed
backend operation so `DockerComposeBackend` and `SshComposeBackend` retain the
same admitted target and transport.

### One admitted extension selection

Reuse the installed `aptl.scenario_startup` seam. Select at most one provider
once from the admitted bundle's exact `PackIdentity` (`pack_id`, version and
set digest), validate its extension API and result, and carry the normalized
selection with the admission. Do not repeatedly call `_runtime_provider()`
during Compose lowering, post-start work and observation. Duplicate,
malformed, load-failed or incompatible matches fail closed with stable bounded
diagnostics.

Keep the purpose-specific incumbent seams separate:

- `aptl.scenario_runtime_parameters` supplies per-run authored parameter
  bindings before planning;
- `aptl.pack_backend_interactions` maps already-admitted component addresses to
  backend operator groups;
- `aptl.scenario_startup` supplies backend-specific startup enrichment; and
- `aptl.scenario_verifiers` supplies a semantic answer key after realization.

They have different authorities and result contracts. A general plugin manager
or a single catch-all scenario object would conflate them.

Portable topology, configuration, generated artifacts, content, readiness
intent, workflow and evidence requirements belong in RAES or the authored pack
whenever a released contract can express them. The installed startup extension
translates only backend-specific gaps. It may supply fixed optional hook slots
such as preparation, bounded pre-retry repair, post-realization setup and
post-readiness integration. It may not add an arbitrary stage graph, re-plan,
choose a different backend, change admitted resources, reinterpret RAES
diagnostics or declare its own success semantics.

An absent extension is valid only when the admitted plan demands none of its
behavior. A tiny scenario with no such demand takes the same admission, apply,
observation and teardown route with an empty extension selection. An advanced
pack whose admitted contract requires unsupported setup or readiness fails
before claiming readiness; it must not silently start an unseeded or
unqualified approximation.

### Typed stages without another public schema

Replace `ctx -> LabResult | None` and the unbounded mutable
`_LabStartContext` at touched seams. Stage functions receive their exact inputs
using the existing DTOs and return one small internal result shape containing:

- an optional typed value needed by the next fixed phase;
- zero or more existing `StartupDiagnostic` values; and
- either continuation or one bounded fatal error.

This result is internal transport. It does not add another public outcome enum,
diagnostic taxonomy, exception hierarchy or API schema. The coordinator alone
derives `StartupOutcome` and constructs `LabResult`. Preserve these incumbent
types rather than mirroring them:

- `AdmittedScenarioStart` for the plan, target, realization and capture plan;
- `AdmittedStartSurface` for its read-only lifecycle projection;
- `ScenarioStartupPlan` or its directly evolved normalized hook contract;
- `AcesRunTarget` and `AcesStartOutcome` for RAES application and run identity;
- RAES `ApplyResult` and `Diagnostic` inside the runtime boundary; and
- `StartupDiagnostic`, `StartupOutcome` and `LabResult` at the lab boundary.

Do not retain `object`, `getattr()` and casts for these known contracts merely
to avoid imports. Put cycle-sensitive coordinator contracts in a leaf module,
as `lab_types.py` already does, and keep imports one-directional. Optional
backend capabilities such as capture activation and operator access must be
declared on the backend contract or an explicit narrow capability protocol;
method presence discovered with `getattr()` is not a contract.

Request-scoped readiness and apply evidence travels in the existing
`DeploymentObservationContext`, RAES snapshot/apply result or another explicit
returned value at that same boundary. Do not use
`_stateful_authenticated_readiness`, another mutable backend attribute, a
module global or process environment as cross-stage state.

### Generic mechanics and scenario-specific choices

The public composition boundary owns lifecycle locking, strict config loading
and the one scenario admission. It passes the settled admission to the generic
coordinator. That coordinator may execute mechanics meaningful for any admitted
scenario: checked residue detection, host capability checks, RAES apply,
declared readiness/observation, capture and operator-access activation,
terminal project attestation, snapshot and run-record publication.

Concrete Wazuh service names and images, Suricata volume seeds, Wazuh daemon
repair, SOC certificate membership, TechVault seed scripts and container
aliases, scenario MCP builds/key maps/config rewrites, and their retry/readiness
choices are not generic phases. Move each choice to authored RAES/pack data or
the one exact startup extension. Retain reusable execution mechanisms in core
or the backend: bounded polling, typed generated-artifact realization,
certificate generation, named-volume seeding, contained script execution,
MCP config shaping, redaction and diagnostics.

A retry remains a bounded re-application of the same admitted plan through the
RAES route. Its trigger is a typed diagnostic code, its attempt count and
deadline are bounded by core, and any scenario-specific repair is one selected
extension hook. Do not parse error prose, sleep without a deadline, re-plan,
or encode Wazuh in the generic coordinator.

## Behavior Parity Contract

The refactor must characterize these current behaviors before moving them and
preserve them unless another owning issue explicitly changes the contract:

| Situation | Required behavior after decomposition |
| --- | --- |
| Complete success | One admission is applied once, all required terminal checks complete, and the public result is `ready` with the real resolved ports. |
| Non-fatal optional failure | Existing diagnostics accumulate and the coordinator derives `degraded_usable` or `degraded_unusable` once. A hook cannot independently reclassify the run. |
| Fatal failure before apply | Return `failed` with prior bounded diagnostics. Do not invoke later stages, fabricate a RAES snapshot or create deployment success evidence. |
| Apply or later fatal failure | Return `failed`, retain RAES/backend diagnostics and owned residual state for explicit recovery, and do not auto-teardown or call the result ready. |
| CLI cancellation or process interruption | Propagate the interruption; the OS lifecycle lock releases. Do not translate cancellation to success, silently retry or infer cleanup. Owned runtime/capture state remains recoverable by the existing stop path. |
| API timeout or client disconnect | Preserve the current truth: `asyncio.wait_for()` does not stop the worker thread. Return an unknown/non-terminal API outcome while the worker retains lifecycle ownership until it exits. |
| Active required transcript | Persist the active authority before exposure. `stop_lab()` finalizes it before removing the sidecar, still attempts teardown when finalization fails, records the failure, and returns the finalization failure. |
| Snapshot and run history | Keep one `AcesRunTarget` per start. RAES workflow history, the terminal `RangeSnapshot`, REP-001 record, provisional REP-003 provenance and correlation projection share that run. Startup remains a provisional record, not an experiment seal. |

The current successful-start run record is best effort and written only after
terminal attestation and snapshot. This refactor must not invent a competing
failure journal or turn a plain lab start into an `ExperimentExecutor` attempt.
Use existing RAES diagnostics, backend ownership receipts, lifecycle state,
active transcript authority and run-store artifacts as the useful history.
Changing which failures receive a durable terminal run record requires a
separate versioned persistence decision.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Public lifecycle | `orchestrate_lab_start`, `clean_boot_lab`, `stop_lab`, `core.kill`, `lifecycle_mutation_lock` and `LabResult` remain one contract projected by CLI/API/web. |
| Config and scenario selection | Strict `AptlConfig`, `DeploymentConfig`, `ScenarioSourceConfig`, `ScenarioCatalog`, `resolve_scenario_selection()`, `resolve_scenario_bundle()`, `ScenarioBundle` and `PackIdentity`. No hook-shaped `aptl.json` map or second pack identity. |
| RAES admission and runtime | `admit_raes_scenario`, `AdmittedScenarioStart`, `start_surface_of`, `RuntimeManager` through `aptl.backends.raes`, RAES planner diagnostics, SEM-218, `ApplyResult` and the runtime snapshot. Do not duplicate planning or validation. |
| Extension discovery | `scenario_startup.py` and the stricter provenance/compatibility patterns in `pack_interaction_discovery.py` and `scenario_verification_discovery.py`: prefilter metadata, exact compatibility, one match, host-observed distribution provenance and bounded returned values. |
| Deployment | `DeploymentBackend`, `DockerComposeBackend`, `SshComposeBackend`, typed realization DTOs, `DeploymentObservationContext`, backend ownership receipts and checked project inventory. Core never assumes a local daemon or Compose implementation mixin. |
| Readiness and retry | Backend realization health, `_compose_service_health`, `_compose_stateful_readiness.ReadinessPolling`, `_declared_listener_readiness`, `core.services.wait_for_service()` and typed RAES diagnostic codes. Keep one owner for each deadline and readiness fact. |
| Secrets and paths | `hydrate_dotenv`, `load_dotenv`, `env_vars_from_dict`, `find_placeholder_env_values`, `update_dotenv_values`, `utils.pathsafe`, owner-only atomic writes, `curl_safe` and `redact`. |
| Errors and observability | RAES `Diagnostic`/`render_raes_diagnostics`, backend error types, `StartupDiagnostic`, `LabResult`, `get_logger()` and existing progress callbacks. Normalize once and keep raw backend/provider output inside its trust boundary. |
| Persistence and evidence | `LocalRunStore`, its finalization lock/redaction/contained writes, `AcesRunTarget`, `RangeSnapshot`, REP-001/REP-003 builders, active transcript authorities, evidence coordinator outcomes and archival terminal-cause contracts. No second repository or run schema. |
| Packaging and release | `pyproject.toml` entry points/package list, `uv.lock`, hashed requirements, `_asset_manifest.py`, `hatch_build.py`, `core.assets`, lab-init installed-wheel tests and the #934 identity ledger. |
| Workflow gates | `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, the TechVault static/live gates, pre-commit, docs build and fresh-machine clean-lab gate whenever Compose, Dockerfiles or `config/` change. |

## Security And Validation Passage

| Layer | Required behavior |
| --- | --- |
| HTTP authentication | Existing `verify_token`, `WebAuthSettings`, `BFFMiddleware` Host/Origin/CSRF/session checks and loopback defaults continue to guard lifecycle routes. A startup extension creates no route and receives no web session or bearer token. |
| Durable config shape | `AptlConfig` and every nested model remain `extra="forbid"`; deployment provider, project name, SSH host/user/key/port, scenario source/root and lifecycle policy pass their existing validators before use. Hook selection is derived from admitted identity, not an env/config import string. |
| Pack and plugin shape | Env-pack staging, content digest and containment validation precede exact provider matching. Validate extension API, identifiers, distribution metadata, supported identity tuple, hook fields, collections, deadlines, profile/address references and result sizes before execution. A provider cannot return raw argv, a module path from scenario data or an unchecked environment map. |
| RAES validation | Public RAES parse, instantiation, semantic compilation, planner diagnostics, manifest capability checks, SEM-218 and runtime snapshot validation remain authoritative. A hook cannot waive a blocking diagnostic or declare an unobserved concern ready. |
| Secret binding | Generate/load secrets through the existing `.env` boundary, pass only declared aliases or credential references, and keep generated files owner-only. Do not pass all of `os.environ` plus `raw_env` to a pack script. No `.env` value, private key, API token, cookie or bearer credential may enter a hook result, progress event, diagnostic or run metadata. |
| Filesystem and executable path | Resolve pack assets from the admitted `ScenarioBundle.root`; use no-follow containment or immutable staged content through execution, not a `resolve()` check followed by a path re-open. Writes use the existing atomic/contained helpers. |
| OS and subprocess exposure | Use fixed argument vectors, existing backend/runners and bounded deadlines/output. Keep credentials and generated config out of argv, URLs and process titles; use `curl_safe`, stdin or restrictive files for secret carriers. A remote Compose run retains its admitted SSH environment and does not fall back to local Docker. |
| Resource ownership | Project name validation, lifecycle lock, Compose/project labels, backend ownership receipts and exact native IDs authorize mutation. An extension's semantic name or pack identity never authorizes reuse, replacement or deletion. |
| Error envelope | Provider, RAES, backend, readiness and script failures become stable redacted diagnostics and the existing result models. Do not expose raw stderr/stdout, command lines, environment, response bodies, host paths, tracebacks or provider object representations through CLI, API, SSE, logs or archives. Legitimate empty, unavailable, incomplete and failed remain distinct. |
| Persistence and telemetry | Structured writes pass `redact()`/run-store boundaries; active capture and finalization use their existing contained create-once state. Log only stage ID, safe component/address, duration, attempt and bounded result code. Do not store a duplicate mutable coordinator checkpoint containing secrets or provider objects. |

## Tiny Profile And Release Boundary

The tiny profile is an ordinary admitted scenario with an empty optional-hook
surface. It must import and start through the same coordinator and RAES/deployment
path in a clean installed environment where imports of all of these are blocked
or absent:

- `aptl_techvault` and TechVault pack bytes;
- Wazuh/MISP/TheHive/Cortex/Shuffle clients and SOC seed assets;
- scenario MCP packages/build scripts and MCP client templates;
- `aptl.workbench` provider integrations; and
- experiment/research policy and participant provider modules.

No-match discovery must avoid importing unrelated entry points. Import-time
dependencies of the generic lifecycle must therefore be leaf contracts and
generic mechanisms; SOC certificate/seed/readiness and MCP modules are loaded
only by the selected advanced path.

Today `pyproject.toml` ships `src/aptl_techvault` inside the core wheel and
registers its startup entry point there. An import-blocked unit test alone is
insufficient proof of a tiny installed profile. Closure needs a built,
installed core-only artifact test, following #878's core/plugin artifact gate
pattern. Do not remove the bundled advanced path until a separately released
replacement is installed, exact-pack compatible, and passes TechVault parity;
record its owner and migration guidance under #880/OpenRAE/lilrae#3. Until that
gate is met, retain the legacy distribution path without letting it become a
tiny-start prerequisite.

## Extensibility Seam And Whole-Repository Scope

The extensibility seam is one normalized, request-scoped startup extension
selected by exact admitted pack identity. Each fixed optional hook receives
only the admitted projection it needs, the applicable narrow backend capability,
the run/attempt identity and a bounded deadline. It returns the one internal
stage-result contract. This permits the next scenario pack to add a different
readiness or post-readiness adapter without editing the coordinator, while
preventing an extension from creating a second scheduler.

The retry seam is parameterized by typed RAES diagnostic code, maximum attempts
and deadline. The readiness seam is parameterized by admitted service/address
and polling budget. The integration seam is parameterized by declared artifact
or server identity and a validated environment/credential projection. Do not
parameterize with `dict[str, object]`, scenario names, profile guesses, arbitrary
callables from config or error-text predicates.

The implementation must inspect these surfaces together:

- `src/aptl/core/lab.py`, `lab_types.py`, `lifecycle_guard.py`,
  `lifecycle_policy.py`, `kill.py`, `config.py`, `env.py`, `services.py`,
  `snapshot.py`, `runstore.py`, provenance, evidence and archival boundaries;
- `src/aptl/backends/raes.py`, `raes_start_model.py`,
  `_raes_scenario_queries.py`, `raes_planning_compat.py`, RAES diagnostics,
  provisioner/observation paths and the runtime workflow adapter;
- `src/aptl/backends/scenario_startup.py`, startup/service policy modules,
  runtime-parameter and pack-interaction discovery, plus `src/aptl_techvault`;
- the deployment protocol, Docker/SSH implementations, ownership, checked
  inventory, health/readiness, stop/cleanup and observation context;
- CLI lab rendering, API dependencies/router/schemas, BFF middleware, web
  lifecycle types and single-flight behavior;
- package metadata, installed assets, dependency pins, requirements exports,
  identity/private-import inventories and installed-wheel gates; and
- focused lab/RAES/backend/adapter/API/evidence tests plus the repository gates.

## Reconciliation Gotchas And Proof Obligations

- `_LAB_START_STEPS` currently admits only after `.env` hydration. Do not call
  secret generation or file mutation admission. The coordinator must consume a
  settled admission before unrelated legacy preparation, while leaving any
  unavoidable RAES artifact availability work inside the documented admission
  boundary.
- `scenario_startup._runtime_provider()` is currently called from startup
  resolution, Compose startup policy, service policy, runtime realization and
  observation. Repeated discovery can load different code/metadata during one
  run and is not a request-scoped contract.
- `_LabStartContext` stores known values as `object`; `lab.py` then uses
  `getattr()` for RAES outcomes, capture plans, operator access and backend
  readiness. This hides missing contracts until late execution.
- `authenticated_readiness` is mutable mixin state read by lab and RAES
  observers. Carry its evidence per apply; a reused backend, retry or concurrent
  admission must not inherit an earlier attempt's proof.
- `_scenario_seed_environment()` currently copies the entire controller
  environment and `.env` into the child. A declared alias list is not a security
  boundary if unrelated ambient secrets still reach the script.
- `seed_script_path()` performs resolve-and-prefix checking but the runner opens
  the path later. Preserve content identity/no-follow guarantees through the
  actual execution boundary.
- Core still contains direct local-Docker discovery for appliance binding and
  TechVault constants, Wazuh repair/readiness, SOC certificate/seed and MCP
  policy. Mechanical file splitting that leaves these decisions in a generic
  coordinator does not satisfy this issue.
- Keep one readiness owner. Backend authenticated readiness, Compose health and
  later lab probes currently overlap; remove a duplicate wait only when the same
  typed, attempt-scoped evidence reaches the terminal decision.
- The known private RAES dependencies are
  `raes._source.ArtifactIdentity`,
  `raes_processor.compiler.addresses._node_address`, and
  `raes_runtime.control_plane_store._snapshot_payload`; the manifest also keeps
  an older-package `ImportError` fallback. Use released public upstream APIs and
  delete the inventory entries, or obtain a published upstream replacement.
  Do not copy their schemas or add another compatibility facade.
- Preserve project-tree/static-Compose compatibility until its released
  replacement passes installed-wheel and TechVault parity with an owner and
  migration note. Absence from the new coordinator is not retirement evidence.

Required characterization covers ready, both degraded outcomes, every fatal
phase boundary, one retry of the same admission, `KeyboardInterrupt`, API
timeout with a live worker, active-transcript finalization success/failure,
remote SSH backend selection, residue/ownership failure, exact/duplicate/absent
extension selection, and a core-only tiny installed artifact. TechVault static
and live qualification must show that moving its hooks preserves advanced
behavior. The private-import inventory must become empty or point only to a
released public replacement; a test allowlist is not closure.

## Non-Goals And Anti-Patterns

This issue does not rename the product, create an experience layer, redesign
RAES schemas, replace `RuntimeManager`, change experiment admission/execution,
add background start jobs or cancellation APIs, redesign evidence sealing,
complete #915's undeclared-mutation removal, or redefine #878 verification.
It does not remove specialized backend behavior still required by a qualified
scenario, and it does not make full TechVault qualification a prerequisite for
the tiny profile.

Avoid these anti-patterns:

- another workflow engine, plugin manager, lifecycle controller, public result
  schema, exception tree, readiness loop, run repository or config section;
- a generic `Hook(name, callable, dict)` list or provider-controlled ordering;
- scenario/display-name, filename, Compose-profile or import-success branches;
- passing `_LabStartContext`, `AptlConfig`, all environment values or a broad
  backend object to code that needs one narrow value/capability;
- treating a running container, successful Compose command, provider return,
  empty diagnostic list or mutable backend flag as RAES realization success;
- retry by re-planning, parsing error prose or using an unbounded sleep;
- loading every installed extension before exact metadata filtering, choosing
  the first match, or silently skipping a required incompatible extension;
- logging or persisting hook inputs/results before validation and redaction; and
- deleting a legacy path because tests no longer import it without released
  replacement, parity, owner and migration evidence.
