# Issue #874 Scenario-Bundle Realization Roots Preflight

This note fixes the architecture guardrails for completing the
`ScenarioBundle` seam introduced by issue #866. It is design guidance, not an
implementation plan. The issue contract is narrow: every filesystem input that
can satisfy scenario-declared realization must resolve from the bundle handed
to APTL, never from APTL's checkout by fallback.

No new ADR is needed. `ScenarioBundle` already owns this boundary, RAES already
owns the scenario and realization schemas, and the deployment layer already
owns Docker and Compose effects. This issue completes those accepted
boundaries. It reverses the transitional comment in
`raes_realization.interpret_provisioning_plan()` that classifies the Compose
profile index as engine infrastructure: the indexed Compose model participates
in binding scenario nodes to concrete services and profiles, so it is
scenario-bundle input.

## Root Ownership And Architecture Decisions

Keep the roots and their meanings distinct:

| Root or identity | Owner | Allowed use |
| --- | --- | --- |
| `ScenarioBundle.root` | The resolved scenario bundle | The SDL's relative assets, `docker-compose.yml`, component contexts under `containers/<id>`, checked-in stateful/config/provenance inputs, and the scenario-local generated-artifact locations consumed and read back by realization. |
| `project_dir` | APTL operator/control-plane configuration | `aptl.json`, operator `.env` and typed secret binding, run-store selection, backend transport configuration, and other engine-owned state. It is not a fallback search path for a missing bundle asset. |
| Compose project name and named-volume identity | `DeploymentBackend` | Runtime isolation and persistent-volume names. These are runtime identities, not filesystem roots, and must not be derived from a bundle path. |
| RAES resource addresses and artifact identities | RAES contracts | Portable scenario, resource, artifact, and evidence identity. A staging path is never promoted to portable identity. |

The in-tree resolver remains the compatibility rule:
`project_tree_bundle(project_dir, scenario_path).root == project_dir.resolve()`.
That equality preserves an unmoved scenario's behavior; consumers must not use
the equality to reconstruct the root. A future acquired-bundle resolver changes
only the bundle it returns.

Resolve the bundle once at scenario ingress and carry that same object through
planning, interpretation, deployment, and readback. Scenario-aware production
paths must not accept `bundle=None` and silently substitute
`project_dir.resolve()`. Query, validation, participant-binding, readiness, and
live-proof paths are realization paths too; they must use the same bundle as
the start path or they can approve a graph that startup realizes differently.

At the deployment boundary, the required seam is an explicitly named
`scenario_root` value derived only from `bundle.root`. It may be threaded
through existing realization/deployment calls where the full bundle is not an
appropriate dependency, but it must not become a second config field, resolver,
DTO schema for scenario identity, or independently defaulted root. Keep
`project_dir` available under its existing name for the operator-owned concerns
above so the two concepts cannot be confused.

The root is realization/request scoped, not mutable singleton state on a reused
backend. A later lifecycle action that needs the source model must either
receive/re-resolve the same bundle through the canonical selector or clean up
from project-scoped runtime identities and labels. It must not rely on a cached
root from the last run, search the checkout, or silently use `project_dir`.
Operational state may retain what lifecycle recovery strictly needs, but an
absolute staging path is not portable realization evidence and must not enter
run records or exported bundles.

The same bundle-rooted Compose model must drive all of:

- the `ComposeProfileIndex` used for node/service/profile binding and dependency
  closure;
- the provisioner's selected-profile validity check;
- steady-state service and network projections used by validation/readiness;
- the base Compose file passed to realization, effective-model validation, and
  stateful teardown;
- build-deduplication inspection and generated Compose overrides.

Do not index one Compose file and execute another. Missing bundle assets fail
closed even when an identically named asset exists in APTL's checkout.
Docker Compose also resolves relative build contexts, `env_file` entries,
includes, and bind sources using its project-directory rules. Therefore an
explicit `-f <bundle-root>/docker-compose.yml` is insufficient by itself:
Compose's effective project directory must be the scenario root (using the
incumbent argv builder), while the operator credential source remains the
validated `project_dir/.env` boundary. Bind the latter explicitly if Compose
interpolation needs it; never allow a bundle-local `.env`, caller cwd, inherited
`COMPOSE_FILE`, or inferred first-file directory to choose either authority.
Only paths, never environment values, may appear in Compose argv.

Component availability and component realization currently duplicate
single-segment checks, containment, Dockerfile lookup, and digest comparison in
`raes_artifact_availability.py` and `raes_image_realization.py`. They must share
one bundle-relative resolution policy. Availability and apply must not disagree
about which `containers/<id>/Dockerfile` was authorized. Preserve the authored
materialization-specification digest and locked-input gates; changing the root
does not relax artifact identity.

Generated artifacts retain their existing typed RAES and deployment records.
The root change belongs in the incumbent path/provider functions
(`artifact_source_path`, stateful model generation, producers, and observation),
not in a new generated-artifact schema. Persistent volumes remain named Docker
volumes; do not invent host paths for them. Checked-in stateful binds and
artifact provenance are bundle inputs, while operator credential values still
come through the control-plane `.env` boundary.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Bundle identity and root | `src/aptl/core/scenario_bundle.py`: `ScenarioBundle`, `ScenarioSourceKind`, `project_tree_bundle()`, and `ScenarioBundle.details()`. Do not add another bundle/root model or include the operational staging path in identity/evidence. |
| Scenario ingress | `ScenarioSourceConfig`, `resolve_scenario_selection()`, `project_tree_bundle()`, `raes.parse_sdl_file`, `RuntimeManager.plan()`, and `_plan_scenario()`. The strict config and catalog path gates remain authoritative; no resolver infers a root by searching parent directories. |
| Filesystem containment | `aptl.utils.pathsafe`, including `read_contained_nofollow()` and `listdir_contained_nofollow()`, plus `ScenarioBundle.read_asset()` for no-follow, one-open reads. Existing generated-output containment, atomic replacement, and mode enforcement in `core.credentials` remain the writer pattern. Do not add a third `PathContainmentError` hierarchy or copy lexical `resolve()/is_relative_to()` checks into each consumer. |
| Artifact admission | `artifact_availability_for_scenario()`, RAES artifact diagnostics, the existing materialization mechanism/profile, locked inputs, exact digest checks, and backend `materialize_component_image()`. Keep address-scoped availability and one materialization per specification. |
| Compose model | `load_compose_profile_index()`, `ComposeProfileIndex`, `select_backend_profiles()`, dependency-closure helpers, effective Compose rendering, and `_build_command()` argv construction. Keep one index/parser and one selected-profile workflow. Extend the typed argv builder with the explicit scenario project-directory/env-file binding rather than assembling a second Compose command path. |
| Stateful realization | `realize_stateful_resources()`, `DeploymentGeneratedArtifactRealization`, `DeploymentPersistentVolumeRealization`, `ComposeStatefulRealizationMixin`, `stateful_realization_errors()`, `stateful_override_payload()`, `artifact_source_path()`, certificate/config producers, and stateful observation/readback. |
| Config and secrets | ADR-025 `AptlConfig`, `load_dotenv()`, `EnvVars`, `env_vars_from_dict()`, `find_placeholder_env_values()`, ADR-028 generated-config writers, ADR-029 redaction, and ADR-034 certificate policy. Bundle rooting does not create a second secret source. |
| Backend effects | `DeploymentBackend`, `DockerComposeBackend`, `SSHComposeBackend`, typed backend exceptions, timeouts, project-name scoping, generated-model validation, and backend readback. RAES adapters do not add raw Docker or shell calls. |
| Errors and observability | RAES `Diagnostic`, `diagnostic()`, `render_raes_diagnostics()`, `ApplyResult`, `LabResult`, `BackendTimeoutError`, `BackendSeedError`, `get_logger()`, and `redact()`. Root failures use existing stable envelopes and bounded messages. |
| Persistence | RAES `RuntimeSnapshot`, `AptlRealization.details()`, `ScenarioBundle.details()`, `RangeSnapshot`, and `LocalRunStore` redacting structured writes. Persist bundle identity/source kind and content digests where already supported, never its absolute staging location or generated secret bytes. |

## Security And Validation Passage

| Layer | Required behavior |
| --- | --- |
| Authentication surface | No new API, CLI option, or remote selector is needed. API-triggered lab actions continue through `verify_token`; local CLI selection continues through the existing scenario selector. A scenario cannot supply a root, module, command, backend, or credential source through SDL. |
| Strict config and resolver shape | `AptlConfig` remains `extra="forbid"`, `ScenarioSourceConfig.root` remains contained operator configuration, and catalog/explicit scenario selection keeps its no-follow path gate. Do not add an unchecked `scenario_root` environment variable or pass-through config mapping. |
| RAES parser and semantic gate | The SDL still passes the RAES parser, compiler, artifact admission, and `RuntimeManager.plan()` diagnostics. Bundle rooting changes where bytes are obtained, not the RAES schema or realization meaning. |
| Bundle path gate | Every authored relative file, Compose file, Dockerfile, provenance file, and checked-in stateful bind is constrained beneath `bundle.root`. Reject absolute paths, traversal, NUL/empty/dot components, and symlink escapes. Prefer `ScenarioBundle.read_asset()`/`pathsafe` no-follow reads over check-then-reopen patterns. |
| Component supply chain gate | A specification ID remains one safe path segment; its Dockerfile must be the bundle copy and must match the authored digest before the existing backend materialization call. A missing, symlinked, drifted, or checkout-only context is unavailable, never substituted. Docker receives fixed argv entries, not scenario-provided shell text. |
| Compose shape and effective-model gate | Parse with the existing safe YAML/mapping validation, then keep `ComposeProfileIndex` normalization and dependency checks authoritative. Before startup, render and validate the same bundle-rooted effective model, including generated image/port/stateful overrides. |
| Stateful graph and generated paths | Reuse stateful graph validation, output-path validation, consumer conflict checks, certificate chain/key/SAN validation, generated-config zero-match rejection, and exact mount readback. Root relocation must not bypass `_canonical_generated_path()`, secure directory modes, atomic writes, or remote-local-artifact refusal. |
| Secret and environment binding | Operator secrets continue to come from `project_dir/.env` through `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, placeholder rejection, and typed service binding; authored non-secret defaults remain RAES data. Compose must not discover a bundle-local `.env` merely because its project directory moved. Secrets do not enter the bundle identity, Compose index, realization details, command line, log text, or diagnostics. Generated secret-bearing directories remain owner-only and excluded from Git, packages, snapshots, and archives even when the bundle is nested below the checkout or staged elsewhere. |
| OS/process exposure | Bundle, Compose, project-directory, and operator env-file paths may appear as non-secret argv operands to the existing typed backend runner. Passwords, tokens, private keys, rendered config, environment values, and credential-bearing URLs do not. Use argv lists and bounded timeouts; do not introduce `shell=True`, command strings, a generic subprocess escape hatch, or ambient cwd/environment precedence for Compose inputs. |
| Error envelope | Bundle/index/policy failures become stable redacted RAES diagnostics; producer/backend failures remain unsuccessful `ApplyResult`/`LabResult` values. Do not expose file contents, raw parser objects, full commands, environment mappings, or unbounded Docker/Compose stderr merely to diagnose the new root. |
| Readback and persistence | Observe generated outputs and mounts against the same root used to produce them. `ScenarioBundle.details()` deliberately omits `root`; retain that rule in snapshots, run records, logs intended as evidence, and exported bundles. Record non-secret identities/digests, not staging locations or generated bytes. |

The repository currently has both `aptl.utils.pathsafe.PathContainmentError` and
the older `aptl.core.credentials.PathContainmentError`. Do not create another
exception or broaden catches so every `ValueError` becomes a security failure.
Use the `pathsafe` type for bundle reads and preserve the credential type only
at the incumbent generated-writer boundary until a separately scoped
consolidation can migrate its callers.

## Extensibility Seam

The next reasonable change is a resolver that acquires or stages a
content-identified bundle outside APTL's checkout. The seam is:

`resolved ScenarioBundle -> bundle.root -> scenario_root at existing deployment helpers`

Adding that resolver must not require edits to profile indexing, component
policy, stateful providers, observation, readiness, or validation. Those
consumers receive the root; they do not inspect `source_kind`, infer parent
directories from `sdl_path`, search the checkout, or know a pack format.
The operational parameter is per realization so one backend instance can
realize different bundles without stale cross-run state.

If a future resolver needs immutable source storage plus a distinct writable
workspace, that is a separate bundle-staging/output-root decision. Do not
anticipate it here with optional roots or fallback precedence. For this issue,
the handed bundle's root is the one realization root and must be writable where
the existing generated-artifact contract requires outputs.

## Whole-Repository Surface In Scope

- Scenario selection and propagation:
  `src/aptl/core/{config,scenario_catalog,scenario_bundle}.py`,
  `src/aptl/backends/raes.py`, `raes_provisioner.py`, and
  `raes_execution_helpers.py`.
- Planning and interpretation:
  `raes_artifact_availability.py`, `raes_image_realization.py`,
  `raes_realization.py`, `raes_profiles.py`,
  `raes_participant_bindings.py`, dependency closure, content placement, and
  stateful realization.
- Compose execution and generated state:
  `src/aptl/core/deployment/{docker_compose,_compose_realization,`
  `_compose_image_realization,_compose_build_dedupe,`
  `_compose_port_realization,_compose_stateful_realization,`
  `_compose_stateful_model,_compose_stateful_services}.py`, certificate/config
  producers, and stateful observation.
- Alternate realization consumers:
  selected-profile and admitted-stateful queries, static/live gates, curated
  live proof, participant readiness/qualification, and scenario-variation
  checks. None may reconstruct `project_dir` as the scenario root.
- Security and evidence:
  `src/aptl/utils/{pathsafe,redaction}.py`,
  `src/aptl/core/{credentials,env,runstore,snapshot}.py`, `.gitignore`,
  asset/package exclusion rules, and ADR-025/028/029/034/044.
- Verification conventions:
  `tests/test_scenario_bundle.py`, `test_scenario_bundle_wiring.py`,
  RAES backend/artifact/stateful/profile tests, deployment stateful tests,
  validation/readiness tests, `pytest`, and `pre-commit run --all-files`.
  Differential fixtures must use distinct checkout and bundle roots with
  contradictory decoys: each root should contain assets the other lacks, and a
  bundle-local `.env` must not override the operator `.env`. Cover the profile
  index, the exact Compose file/project directory executed, component
  availability and apply, generated-artifact production and observation,
  stateful teardown/recovery, checkout-only failure, symlink refusal, and the
  unchanged in-tree resolver.

## Gotchas And Anti-Patterns

- Do not mechanically rename every `project_dir` parameter. Some uses are
  correctly operator-owned. Classify the data being resolved, then pass the
  correct root explicitly.
- Do not retain `bundle=None -> project_dir` in a scenario-aware production
  path. Compatibility comes from the in-tree resolver returning `project_dir`,
  not from a second fallback.
- Do not fix only the public start path. The current selected-profile,
  admitted-stateful, participant-binding, execution-details, gate, and
  readiness paths can otherwise validate against APTL's tree.
- Do not load the profile index from the bundle and later validate/start/tear
  down with APTL's `docker-compose.yml`.
- Do not pass only `-f` and assume Compose will resolve relative contexts,
  `env_file` entries, includes, binds, or `.env` from the intended authority.
- Do not store a "current scenario root" on a reusable backend and let a later
  request, retry, status check, or teardown inherit it.
- Do not let an APTL checkout-only Dockerfile, Compose service, stateful config,
  certificate provenance file, or generated output satisfy a bundle rooted
  elsewhere.
- Do not preserve two copies of component ID/path/digest validation. Drift
  between availability and realization is an admission-versus-apply bug.
- Do not use `Path.resolve()` plus `is_file()` followed by a later
  `read_bytes()` as a new bundle-read pattern; it follows symlinks and reopens
  after validation. Reuse the no-follow boundary.
- Do not put operational roots into `ScenarioBundle.details()`,
  `AptlRealization.details()`, runtime snapshots, reproducibility records, or
  exported evidence. Location is not scenario identity.
- Do not move secret-bearing generated files beneath a configurable/nested
  bundle root without preserving owner-only modes and Git/build/archive
  exclusions. The current root-relative ignore entries are a regression risk.
- Do not make the SSH backend accept controller-local generated bind sources.
  Preserve `supports_local_artifacts=False` until a separately designed remote
  staging and integrity-verification boundary exists.
- Do not treat persistent volumes as host directories merely because adjacent
  generated artifacts have a filesystem root.
- Do not add a scenario-root setting to SDL, a second Pydantic schema, a
  backend-specific exception family, or root selection based on scenario,
  component, service, or profile names.

## Non-Goals And Boundaries

This issue does not implement pack acquisition, add a new scenario source kind,
make arbitrary external CLI paths trusted, redesign RAES schemas, change
artifact identities or materialization mechanisms, redesign Docker Compose
profiles, replace the deployment backend, change project-name or named-volume
semantics, or merge the legacy containment exception classes. It does not
change API authentication, participant authority, network exposure, secret
precedence, run-store layout, readiness taxonomy, or evidence schemas.

It also does not make component builds reproducible from a Dockerfile digest
alone, redesign certificate generation, introduce remote generated-artifact
transport, or separate immutable bundle storage from a writable realization
workspace. Those require their own contracts. The implementation boundary is
root authority and propagation: a scenario-declared filesystem input is
satisfied only by the bundle APTL was handed, while an in-tree bundle remains
behaviorally unchanged because its root is the project directory.
