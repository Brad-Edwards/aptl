# Issue #951 Fresh Env-Pack Start Preflight

This note fixes the architecture boundary for the clean-install startup
regression in issue #951. It is design guidance, not an implementation plan.
No new ADR is needed: the accepted authorities are already
[the scenario-bundle root boundary](issue-874-scenario-bundle-realization-roots-preflight.md),
[the env-pack admission boundary](issue-875-scenario-content-declaration-preflight.md),
[the certificate producer boundary](issue-677-cert-producer-ownership-preflight.md),
and [the lifecycle cleanup boundary](issue-905-lab-lifecycle-robustness-preflight.md).

## Architecture Decisions

### Resolve and admit the selected bundle once

Scenario selection has one precedence rule: an explicit catalog/path selection
is a project-tree bundle; otherwise `ScenarioSourceConfig` selects the configured
env-pack or project-tree source. `config.scenario.source` therefore does not, by
itself, describe the source of the scenario being started. Code that skips a
legacy producer because the config default says `env-pack` is wrong when the
operator supplied a catalog or explicit path.

The public start must reuse `resolve_scenario_bundle()`. A missing default
project-tree filename must not be substituted before that resolver runs, and a
missing file must not silently mean “no ownership.” In particular,
`DEFAULT_RAES_SCENARIO` is not the default env-pack's location and must not be
used by lab-start preflight when `scenario_path is None`.

Resolve the `ScenarioBundle`, parse it, create the `RuntimeTarget`, and produce
the RAES `ExecutionPlan` once. The same target, plan, and
`AptlProvisioner.realize_plan()` result must drive pre-mutation decisions and
the later `RuntimeManager.apply()`. Reuse the provisioner's existing cached
`AptlRealization`; do not create a second ownership DTO, reparse/replan in
`_load_stateful_artifact_ownership()`, or stage the same env-pack twice.
Request-scoped orchestration may carry these existing objects through
`_LabStartContext`; they are not a new persisted or public schema.

### Validate the model that will actually be applied

The bind-source preflight has one narrow purpose: stop Docker from fabricating
a missing host source as a root-owned directory. It is not an alternate
authority for scenario membership, generated-artifact consumers, or mount
destinations.

For a project-tree bundle, the static `docker-compose.yml` remains the model and
its bind check is a compatibility guard. It must be limited to the profiles
selected by the admitted realization, not the broader `AptlConfig.containers`
ceiling. This is what keeps a reduced catalog scenario from validating SOC
services it does not start.

For an env-pack bundle, the project directory's `docker-compose.yml` is not an
input to realization. The backend generates the base model and its stateful and
content overrides from `DeploymentRealizationSpec`. Lab orchestration must not
scan the unrelated static file. Bind-source existence belongs in the existing
fully merged, `--no-interpolate` effective-model validation after generated
artifacts and content have been materialized and before `compose up`.
`effective_stateful_model_errors()`, provider output checks, and content
placement/readback remain the semantic validators; do not reproduce them in
`core.lab`.

Mount targets are still checked against the admitted consumer contract in the
backend's effective-model validation. Do not compare a target from the static
Compose compatibility model with a target from the env-pack realization. If a
narrow compatibility exemption is retained during migration, its existence
claim may match only the exact admitted service plus canonical generated source
under `DeploymentBackend.realization_root`; destination matching remains the
effective model's job. No scenario name, service allowlist, TechVault path, or
certificate filename may select the exemption.

Generated output paths for an env-pack are rooted at the backend's writable
`realization_root` (`project_dir` for local Compose), not the pristine staged
`ScenarioBundle.root`. The pack root remains the authority for immutable input
bytes. Confusing these roots recreates the same defect with a different path.

### Prove the distributed artifact and cleanup contract

The regression gate must exercise the product users install, not an editable
checkout. Build the wheel with the existing locked, no-isolation toolchain;
install locked runtime dependencies plus that wheel into a clean virtual
environment; do not install the project editable or copy ignored generated
state. Run the public `aptl lab init`, start
`techvault-observability-core`, and run `aptl lab stop -v --yes`.

Teardown verification is project-scoped. Reuse the identities and query rules
from `observe_project_runtime()` and `_compose_volume_cleanup`: both Compose and
direct-materializer container labels, the Compose project network label, and
the validated `<project_name>_` volume namespace. Assert zero containers,
networks, and volumes. Never use names such as `aptl-*` as the sole authority,
and never use a daemon-wide prune. Cleanup must run on failure as well as
success, while a failed start or failed cleanup still fails the job.

The `5.2.1` version and changelog are release-please outputs. The fix PR needs a
`fix:` Conventional Commit title; implementation must not hand-edit
`pyproject.toml`, `src/aptl/__init__.py`, `CHANGELOG.md`, or the release manifest
to publish the patch.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Scenario selection and source | `ScenarioCatalog`, `resolve_scenario_selection()`, `ScenarioSourceConfig`, `resolve_scenario_bundle()`, `ScenarioBundle`, and `ScenarioSourceKind`. Explicit selection precedence stays in the resolver. |
| Pack ingress | `env_pack_bundle()`, `validate_pack()`, `validate_pack_content_manifest()`, per-invocation contained staging, and `aptl.utils.pathsafe`. No local pack schema or fallback search. |
| Admission and interpretation | `_plan_scenario()`, RAES parser/compiler/planner diagnostics, `RuntimeTarget`, `ExecutionPlan`, `AptlProvisioner.realize_plan()`, `AptlRealization`, and `DeploymentRealizationSpec`. One admitted execution, not a query plan plus an apply plan. |
| Generated artifacts | `raes_stateful_realization.py`, `artifact_source_path()`, `ComposeStatefulRealizationMixin`, `stateful_realization_errors()`, provider-specific output validation, and `DeploymentBackend.realization_root`. |
| Compose model | `base_compose_file()`, `_realization_compose_files()`, `_validate_realization_compose_model()`, `effective_stateful_model_errors()`, and `_build_command()`. Validate the merged model with no interpolation; do not add another Compose parser. |
| Config and secrets | Strict `AptlConfig` models, `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, placeholder rejection, owner-only generated files, ADR-029 redaction, and explicit `project_dir/.env` Compose binding. |
| Results and observability | RAES `Diagnostic`, `render_raes_diagnostics()`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, `get_logger()`, and `redact()`. No new exception hierarchy or API envelope. |
| Distribution | `_asset_manifest.py`, `hatch_build.py`, `assets.materialize()`, `.gitignore`, wheel-content tests, locked requirements, and the existing release workflow. Generated certs, keys, `.env`, and `.aptl/` remain absent from artifacts. |
| Lifecycle cleanup | `lifecycle_mutation_lock()`, `stop_lab()`, `stop_compose_lab()`, `observe_project_runtime()`, project-label cleanup, and `project_scoped_volume_names()`. |

## Security And Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| Auth surface | This issue adds no endpoint or authorization decision. Existing API token, Host, CSRF, session, and CLI boundaries remain unchanged; the CI job uses only the local CLI. |
| Config shape | `aptl.json` continues through Pydantic models with `extra="forbid"`; scenario identity/source and validated `deployment.project_name` remain the only durable selectors. Add no bind-preflight toggle, service list, or path map. |
| Catalog/path gate | Catalog entries and explicit paths pass the existing id schema, no-follow project containment, and RAES parse validation. An explicit path is never reclassified from the config default. |
| Pack shape and bytes | Env-pack acquisition passes both public env-packs validators, exact inventory/digest checks, no-symlink/hardlink/special-file rules, and contained immutable staging. A missing/rejected pack fails closed as `EnvPackError`; it never falls back to a deleted project path. |
| RAES shape and policy | Generated outputs, consumers, service bindings, access modes, sensitivity, dependencies, and destinations pass RAES validation and APTL's existing typed lowering/stateful graph checks before mutation. |
| Filesystem and secret handling | Immutable pack input uses `ScenarioBundle.root`; generated output uses `realization_root`; operator secrets use `project_dir/.env`. Preserve canonical contained paths, no-follow checks, atomic writes, restrictive modes, declared-output completeness, and package exclusions. No PEM, private-key, token, or env bytes enter mount metadata or evidence. |
| Compose/effective model | Use the existing argv-list runner, explicit project directory/env file, bounded timeouts, `--no-interpolate`, and normalized effective model. Do not serialize, log, or persist the rendered model because it can carry sensitive configuration. |
| OS/process exposure | Only non-secret paths and fixed Docker/Compose options may appear in argv. Do not add `shell=True`, command strings, credential-bearing URLs, env dumps, or raw Docker output. Local/SSH visibility continues through `supports_local_artifacts` and the existing remote-artifact refusal/probe boundaries. |
| Error envelope | Pack/parser/planner errors become bounded, redacted diagnostics; producer/backend failures stay unsuccessful `LabResult`/RAES apply results. Do not expose raw YAML parser context, absolute staging roots, full commands, Compose stderr, tracebacks, or environment mappings. |
| Logging/persistence | Log bounded phase, source kind, stable diagnostic code, service/address, and counts through `get_logger()`/`redact()`. `ScenarioBundle.details()` continues to omit roots; run records retain identities/digests and outcomes, never generated bytes or operational paths. |
| CI authority | Keep workflow permissions read-only, pin actions by SHA, use hashed dependency exports, install the wheel with `--no-deps` after the locked runtime set, and scope every Docker assertion to the validated Compose project identity. |

## Extensibility Seam

The seam is the already-selected, request-scoped `ScenarioBundle` plus the one
admitted `ExecutionPlan` and cached `AptlRealization`. The next pack identity,
catalog scenario, or immutable acquisition mechanism changes the resolver input;
it does not add branches to lab steps or teach the static Compose checker about
new services.

The bind-validation parameter is the actual model source (`project-tree` static
model or generated effective model) and its backend `realization_root`. A future
remote-materialization implementation can change how that backend proves source
existence without changing RAES, the catalog, or lab orchestration. The CI
scenario id and project name are explicit inputs; resource assertions derive
from the project identity rather than copied container/network lists.

## Whole-Repository Surface In Scope

- Selection/admission: `src/aptl/core/{config,scenario_catalog,scenario_bundle,lab}.py`
  and `src/aptl/backends/{raes,_raes_scenario_resolution,_raes_scenario_queries,raes_provisioner,raes_realization}.py`.
- Realization: `src/aptl/core/deployment/{backend,docker_compose,realization,`
  `_compose_realization,_compose_model_realization,_compose_stateful_*,`
  `_compose_content_mounts}.py`.
- Secrets/errors: `src/aptl/core/{env,credentials,soc_ca,lab_types}.py`,
  `src/aptl/utils/{pathsafe,redaction,logging}.py`, and CLI/API result projections.
- Distribution/workflow: `src/aptl/_asset_manifest.py`, `hatch_build.py`,
  `pyproject.toml`, locked requirements, `.gitignore`, `.github/workflows/checks.yml`,
  `.github/workflows/release-please.yml`, and `docs/releasing.md`.
- Cleanup: lifecycle lock/orchestration plus `_compose_stop`,
  `_compose_runtime_inventory`, `_compose_project_cleanup`, and
  `_compose_volume_cleanup`.
- Verification: lab, scenario-bundle/catalog, env-pack, stateful/effective-model,
  asset/wheel, lifecycle/cleanup, and current-catalog scenario tests. The public
  catalog is data; coverage must not copy a fixed count of four entries now that
  the repository contains another catalog scenario.

## Gotchas And Anti-Patterns

- Do not infer actual source kind from `config.scenario.source` after an
  explicit scenario path has won selection.
- Do not replace `None` with `DEFAULT_RAES_SCENARIO` before env-pack resolution,
  and do not silently return when that deleted file is absent.
- Do not resolve/stage the bundle once for display, again for ownership, and a
  third time for apply. Distinct staging paths are not proof of one admitted
  execution.
- Do not compare static-Compose destinations with generated-model destinations
  or weaken destination validation globally to make two unrelated models agree.
- Do not compute generated source paths from the pristine pack root when the
  backend writes them under its realization root.
- Do not key behavior on `techvault`, `misp`, `thehive`, `shuffle`, `cortex`, a
  certificate filename, or `/opt/aptl/soc-certs`.
- Do not add another tuple/DTO mirroring generated artifacts, another YAML or
  Compose schema, another validation pass, or another exception hierarchy.
- Do not treat a developer's ignored generated state as a fixture. Start tests
  from `assets.materialize()`/the public init path and assert the relevant
  generated roots are initially absent.
- Do not let the wheel CI use `pip install -e .`, the source checkout's CLI,
  or a separately installed local integration plugin; those bypass the released
  artifact contract under test.
- Do not make teardown best-effort in CI, assert only running containers, or use
  broad name prefixes/global prune. Include stopped containers, networks, and
  volumes, and fail when absence cannot be proved.
- Do not hand-edit release versions or changelog entries for `5.2.1`.

## Non-Goals And Boundaries

This issue does not redesign RAES or env-packs schemas, change scenario content,
add a pack-specific provider, migrate all legacy project-tree producers, add a
deployment backend, weaken TLS/credential policy, alter participant behavior or
readiness, or make remote Docker consume controller-local generated files.

It does not make `docker compose up` a supported replacement for `aptl lab
start`, ship generated credentials/certificates in the wheel, rename services,
or revise the intended topology. The implementation boundary is correct
scenario selection, one admitted realization, validation of the model actually
applied, clean wheel-installed startup, project-scoped teardown proof, and the
normal automated patch-release workflow.
