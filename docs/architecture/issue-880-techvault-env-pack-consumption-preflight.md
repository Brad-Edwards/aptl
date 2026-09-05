# Issue #880 TechVault Env-Pack Consumption Preflight

This note reconciles issue #880 with the repository state on 2026-09-05. The
physical TechVault pack already exists in `OpenRAE/env-packs/packs/techvault`;
this issue is now APTL cleanup, uniform acquired-pack consumption, and parity
evidence. It is architecture guidance, not an implementation plan. It does not
choose a future pack repository or authorize recreating or moving the pack.

No new ADR is needed. The accepted
[pack/backend interaction seam](../adrs/adr-053-pack-backend-deployment-serving-interaction-seam.md)
and the existing
[bundle-root](issue-874-scenario-bundle-realization-roots-preflight.md),
[content-declaration](issue-875-scenario-content-declaration-preflight.md), and
[fresh-start](issue-951-fresh-env-pack-start-preflight.md) boundaries already
own the mechanisms. Proposed ADR-054 through ADR-058 define the broader LilRAE
ownership and qualification direction without changing this issue into a
migration project.

## Reconciled Baseline

The locked `raes-env-packs==4.0.2` distribution currently yields this validated
identity through `env_pack_bundle()`:

| Field | Validated value |
| --- | --- |
| Pack id | `techvault` |
| Pack version | `0.1.0` |
| Associated-artifact set digest | `sha256:c532775575d99438f4b4890d49a4fdb7354921f0405afdaa9f370ea4fe3f5a20` |
| SDL entry point | `sdl/techvault.sdl.yaml` |
| Declared maturity | `built`, not `golden` |

That release contains the full TechVault scenario only. The four curated
reduced SDLs and bounded-participant SDL in APTL's `scenarios/catalog.json` are
not entries in this acquired pack. They must not be synthesized from the full
pack, represented as acquired content, or retained as shadow copies merely to
keep current catalog ids working. Their separate pack/release and qualification
issues own their future.

The current pack also declares APTL-contained component materializations with
empty `locked_input_ids`. Its exact pack inventory binds the pack bytes; it does
not bind every APTL build-context input or establish golden-range proof. Closure
evidence must state that limitation unless a newly released, newly identified
pack closes it. A changed release gets a new exact identity and compatible
provider/evidence; do not edit or alias the identity locally.

## Architecture Decisions And Guardrails

### One catalog selection must enter one acquisition path

Default selection already uses the intended boundary:

`ScenarioSourceConfig -> resolve_scenario_bundle() -> env_pack_bundle() -> ScenarioBundle`

`--scenario <catalog-id>`, `aptl lab scenarios`, and the scenario list/detail
API currently bypass it by reading `scenarios/catalog.json` and collapsing a
catalog id to an APTL-relative `Path`. That path is then deliberately classified
as `project-tree`, even while the configured default is `env-pack`. This is the
privileged second ingestion path issue #880 must eliminate.

A catalog entry is an operator-facing selector and presentation projection; it
is not a second content package or a host locator. A TechVault selection must
select the existing `ScenarioSourceConfig` identity and then return the one
validated `ScenarioBundle`. The CLI start, CLI list, API list/detail, static
validation, live validation, and normal lab start must parse/project the SDL
from that acquired bundle. An explicit `--scenario-path` remains a contained
project-tree development escape hatch and must stay visibly distinct from an
acquired pack selection.

This supersedes only issue #951's transitional statement that a *catalog id* is
always a project-tree bundle. Its one-resolution/one-admission, generated-model,
secret, failure, and clean-install rules remain in force. Do not add a union of
APTL pack metadata fields to `ScenarioCatalogEntry`, parse `pack.yaml` locally,
or create a second pack/catalog schema. Reuse env-packs' public validation and
catalog/acquisition contracts and keep APTL's current catalog metadata models
only for backend/UI facts RAES and env-packs do not own.

Resolve and admit once per operation. The same `ScenarioBundle`, parsed RAES
scenario, execution plan, cached `AptlRealization`, and exact pack identity must
drive projection, pre-mutation decisions, apply, readback, and run evidence.
Repeated staging paths are transient copies, not distinct identities and not a
reason to re-plan.

### Identity is content identity, never a path or friendly scenario name

`env_pack_bundle()` remains the only current pack ingress. It copies the
installed source to a fresh isolated tree, applies `validate_pack()` and
`validate_pack_content_manifest()`, and returns `PackIdentity` on
`ScenarioBundle`. Every exact content placement continues through
`resolve_pack_artifact()` and its digest comparison. APTL must not re-read
`pack.yaml`, derive identity from `techvault`, hash an SDL as a replacement, or
fall back to `scenarios/` after any failure.

The validated pack id/version/set digest belongs in existing
`backend_evidence.pack_interaction`. Provider distribution/version, entry point,
mapping digest, and selected profiles remain separate backend-serving evidence.
For an acquired bundle, `RunRecordInputs` must not persist the absolute,
per-invocation staged `sdl_path` as reproducibility identity. Preserve the RAES
scenario/lock evidence shape, but use a bounded bundle locator/display value and
the validated pack identity; never persist the staging root.

Content integrity and publisher authenticity are different claims. The current
package-resource resolver establishes exact content identity under the trust
of the installed Python distribution. If acquisition is later expanded to an
archive or remote source, use env-packs' `stage_pack_archive()`,
`plan_install()`/`apply_install()`, and `verify_pack_release()` policy surface.
Do not add a URL downloader, signature format, trust store, or authenticity
claim in this issue.

### Remove content by ownership, not by filename or hash alone

The residual inventory has at least four ownership classes:

| Class | Current examples | Rule |
| --- | --- | --- |
| Pack-owned scenario declarations | `scenarios/catalog.json`, TechVault SDLs, `scenarios/archive/` scenario material | Remove from the APTL runtime/distribution once every active consumer uses the acquired bundle. Historical evidence may remain clearly historical. |
| Exact pack-content duplicates | Wazuh TechVault rule/decoder files, DB seed SQL, DNS zone/config, fileshare config, `custom-shuffle`, and the webapp tree | Retain one active owner: the validated pack artifact. No checkout fallback or copied fixture. |
| Backend mechanism and substrate | RAES adapters, generated Compose, content materializers/readback, generic substrate, operator control key, safe persistence, and generic container mechanisms | Keep in APTL when the code is scenario-independent and selected by admitted typed requirements. |
| Pack/backend integration | `aptl-techvault-pack-interaction` exact component-to-operator-group provider | Keep out of core and exact-identity-bound under ADR-053. Release evidence installs a packaged provider, never an editable checkout. Repository relocation is not decided here. |

Hash equality is useful inventory evidence, not ownership authority. In
particular, the pack's `misp-sync-src.tar` contains a broad historical
`src/aptl` snapshot. That does not make APTL core scenario content or authorize
deleting it. Conversely, a renamed or transformed checkout file can still be
scenario content. Classify by declaration, active consumer, mutation owner,
and readback contract.

Component build contexts are also not planted scenario content. The acquired
SDL currently digest-selects several APTL-contained materialization
specifications under `containers/`. Do not delete a selected context until the
acquired release selects an available replacement artifact. Do not call its
Dockerfile-only digest a lock for the empty `locked_input_ids`; qualification
must disclose the actual verified input set.

`_asset_manifest.py` stays the single build/runtime inventory for
`hatch_build.py` and `assets.materialize()`. Narrow that canonical inventory
based on proven runtime ownership. Do not add a second wheel denylist or let
the source-checkout and installed-wheel selections drift. Direct APTL wheel
contents and separately installed dependency contents are separate facts:
shipping an env-pack alongside APTL is permitted, but its proximity cannot
bypass acquisition or make its bytes APTL-owned.

### Startup behavior follows admitted requirements, not pack identity

`ScenarioSourceKind` is provenance; it is not a feature flag. The existing
`_scenario_is_env_pack()` branches for pivot/authorized-key generation and SOC
certificates conflate source with declared artifact ownership. Pre-realization
steps must use the admitted typed `stateful_artifact_ownership`, selected
profiles, and backend capability. `_step_generate_certs()` already demonstrates
the ownership-driven pattern. Unsupported generated-artifact generator/profile
pairs continue to fail closed in the exhaustive stateful provider dispatch.

Pack-specific producer profile identifiers are acceptable only as exact inputs
to a typed backend mechanism with output, sensitivity, containment, consumer,
and cryptographic validation. They must not spread into catalog selection,
generic lifecycle ordering, Compose service discovery, or config flags.
`DEFAULT_RAES_SCENARIO` is a stale path to a deleted local document and must not
remain an active runtime fallback or be replaced by a different TechVault
constant.

The remaining lifecycle includes credential sync, Suricata seeding, readiness,
retry, SSH checks, SOC seeding, and MCP setup. Issue #880 should remove any
source/name-based privilege those steps depend on and prove required steps are
selected from admitted state. It is not a mandate to perform issue #970's full
lifecycle decomposition or issues #915--#918's broader mutation redesign.

### Parity evidence is layered and identity-scoped

Structural parity must come from the installed artifacts: the APTL wheel has no
active TechVault SDL, catalog, or copied scenario bytes; default, catalog, API,
static-gate, and start selections report the same validated pack identity; and
a missing, corrupt, unknown, or extra pack member fails without touching a
local decoy. Wheel inspection must distinguish APTL's direct bundle from the
separately packaged env-pack dependency.

Runtime parity must exercise the full acquired TechVault SDL through the public
start path with the packaged, exact-compatible interaction provider. The
evidence binds CLI, RAES, env-packs, pack/provider, image, Docker/Compose, and
platform versions; admitted and selected resources; generated Compose; native
content and service readback; semantic verifier results when available; reset;
teardown; residual state; durations; and limitations. Reuse the current run
record, snapshot, verification-plugin, and project-scoped cleanup surfaces.
Local variant boots, editable installs, mocks, static validation, or container
health cannot substitute for this evidence.

Keep claims separate: content relocation, exact pack-byte identity, backend
realization parity, scenario semantic success, and golden reference maturity
are five different facts. Passing the first three does not establish the last
two. Evidence applies only to the exact pack set digest and compatible provider
mapping; another release does not inherit it.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Selection/config | Strict `ScenarioSourceConfig`/`AptlConfig`, `resolve_scenario_selection()`, `resolve_scenario_bundle()`, and `ScenarioBundle`. Converge the selector on this seam; do not add another resolver. |
| Pack ingress/identity | `env_pack_bundle()`, env-packs `validate_pack()`, `validate_pack_content_manifest()`, `resolve_pack_artifact()`, validation limits, isolated staging, and `aptl.utils.pathsafe`. |
| Scenario semantics/admission | RAES parser, compiler, planner, `RuntimeTarget`, diagnostics, `AptlProvisioner`, `AptlRealization`, and `DeploymentRealizationSpec`. No APTL SDL mirror or second admission workflow. |
| Pack/backend serving | ADR-053's `PackBackendInteractionContext`, exact provider discovery, `BackendIdentity`, `OPERATOR_GROUP_VOCABULARY`, `public_start_profiles()`, immutable total mapping, and core unprofiled default. |
| Content/component realization | `artifact_availability_for_scenario()`, declared materialization specifications, `raes_content_realization`, `resolve_pack_artifact()`, typed materializer operations, Compose content mounts, and native read-after-write checks. |
| Generated state | `raes_stateful_realization`, `DeploymentGeneratedArtifactRealization`, `stateful_artifact_ownership`, `ComposeStatefulRealizationMixin`, canonical generated paths, provider output checks, and `DeploymentBackend.realization_root`. |
| Compose/effects | `render_realization_compose()`, `base_compose_file()`, generated stateful/content overrides, normalized effective-model validation, project identity, and argv-list backend runners with timeouts. |
| Errors/logs | `EnvPackError`, existing `ScenarioError` subclasses, `PackBackendInteractionError`, RAES `Diagnostic`, unsuccessful `ApplyResult`/`LabResult`, `get_logger()`, and `redact()`. Do not add an exception hierarchy or public error envelope. |
| Persistence/evidence | `RunRecordInputs`, `build_reproducibility_record()`, `backend_evidence`, `derive_identity()`, `LocalRunStore`, native snapshots/readback, and the scenario-verifier entry-point seam. No new repository or evidence schema for packs. |
| Distribution/workflow | `_asset_manifest.py`, `hatch_build.py`, `assets.materialize()`, `pyproject.toml`/`uv.lock`/hashed requirements, wheel-inventory tests, and `.github/workflows/checks.yml`. |

## Security And Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| HTTP/auth surface | Scenario API routes remain behind `verify_token` and `BFFMiddleware` Host, CSRF, and session gates. The issue adds no unauthenticated acquisition/install endpoint, URL selector, or plugin-install control. CLI selection remains local operator authority. |
| Config/env shape | `aptl.json` continues through Pydantic models with `extra="forbid"`; source and identity are bounded typed selectors. `project_dir/.env` remains the operator credential source through `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, and placeholder rejection. A pack-local env file cannot override it. |
| Catalog/selector shape | Validate ids and mutual exclusivity once. Catalog data selects the canonical source resolver; it never supplies a host path, import target, command, environment-variable name, or arbitrary pack metadata. Explicit paths retain no-follow project containment. |
| Pack shape/bytes | Treat bytes as untrusted until both env-packs validators pass. Preserve exact inventory/set/per-member digests, bounded limits, no symlink/hardlink/special-file acceptance, isolated staging, and digest-bound `resolve_pack_artifact()` reads. Missing, extra, changed, or unknown content fails closed with no local fallback. |
| RAES/policy gate | Parsed SDL, exact artifact availability, materialization specifications and locked inputs, generated outputs/consumers, topology, mounts, ports, Linux capabilities, Docker authority, and observation requirements pass existing RAES and APTL admission before deployment mutation. Operator policy remains distinct from authored demand. |
| Filesystem/secret boundary | Immutable input is rooted at `ScenarioBundle.root`; generated output is rooted at backend `realization_root`; operator state remains at `project_dir`. Reuse no-follow containment, canonical destinations, atomic owner-only writes, declared-output completeness, read-only least-privilege mounts, and crypto/key-pair checks. |
| Effective Compose/runtime | Generate from typed realization and validate the fully merged `--no-interpolate` model. Preserve loopback publication policy, project labels/namespaces, foreign-resource refusal, backend-local artifact constraints, and native readback. Do not log or persist rendered Compose. |
| OS/process exposure | Use argument lists, fixed executables, explicit working/project directories and env files, and bounded timeouts. Non-secret operational paths may appear in local argv; tokens, private keys, passphrases, env values, credential-bearing URLs, authored shell, and pack-selected executable names may not. No `shell=True`. |
| Error envelope | Expected catalog/pack/parser/provider failures map into the existing redacted exceptions/diagnostics and CLI exit or API 404/502 envelopes. Do not expose raw parser/Pydantic/provider/subprocess text, tracebacks, absolute stage paths, commands, environment maps, or Compose stderr. |
| Logging/persistence | Log bounded phase/code/count, source kind, exact non-secret identity, and host-observed provider metadata via `get_logger()`/`redact()`. Persist exact identity, selected profiles, mapping digest, native outcomes, and limitations; omit staged roots, raw pack/catalog payloads, secrets, and generated bytes. |

## Extensibility Seam

The required parameter is the scenario source selector handed to the existing
bundle resolver, with pack `identity` already data rather than a TechVault
constant. The resolver returns one validated `ScenarioBundle` with exact
`PackIdentity`; every downstream consumer depends on that bundle and admitted
realization, not on catalog storage or acquisition location. A next pack id can
therefore vary configuration/catalog data and an installed exact interaction
provider without editing lab steps, the Compose renderer, API DTOs, or evidence
storage.

If the next acquisition source adds a version/digest selector, archive, remote
catalog, or trust policy, that variation belongs behind this resolver and
env-packs' public install/release gates. It must not introduce another catalog
locator union or teach deployment code about package resources and URLs.

## Whole-Repository Surface In Scope

- Selection/projection: `aptl.json`, `src/aptl/core/{config,scenario_catalog,scenario_bundle}.py`,
  `src/aptl/cli/lab.py`, `src/aptl/api/{routers/scenarios,scenario_projection,schemas}.py`,
  and their web DTO consumers.
- Admission/realization: `src/aptl/backends/{_raes_scenario_resolution,raes,`
  `raes_artifact_availability,raes_content_realization,raes_realization,`
  `raes_stateful_realization,raes_pack_interaction}.py` and the deployment
  model/materializer/effective-Compose layers.
- Lifecycle/security: `src/aptl/core/{lab,ssh,env,credentials,soc_ca}.py`,
  generated-artifact providers, `aptl.utils.pathsafe`, logging/redaction,
  project ownership, host-port policy, and local/SSH backend boundaries.
- Persistence/qualification: `raes_repro.py`, run records, snapshots,
  verification plugins/gates, native observation, reset/teardown, and exact
  limitation reporting.
- Content/distribution: `scenarios/`, the semantically owned subsets of
  `config/`, `containers/`, and `scripts/`, the TechVault interaction plugin,
  `_asset_manifest.py`, `hatch_build.py`, dependency locks, docs, and installed
  wheel/dependency inventories.
- Workflow: scenario/catalog/bundle/content/stateful/pack-interaction tests,
  wheel tests, the RAES static gate, fresh-start preflight, clean installed lab
  boot, release reports, `pytest`, `pre-commit run --all-files`, and the clean
  runtime gate required by `.gc/plan-rules.md` when deployment assets change.

## Gotchas And Anti-Patterns

- Do not move TechVault again, vendor it, select a permanent repository, or
  edit acquired pack bytes from APTL.
- Do not keep local SDL/catalog/config copies as a fallback, test fixture, or
  “in-box optimization.” A failed acquired pack is a failed selection.
- Do not claim the local curated variants are in the released pack or treat
  catalog presence, static validation, `built` maturity, or container health as
  golden/full-range proof.
- Do not use scenario name, catalog id, source kind, service name, profile name,
  or a familiar path to decide content ownership or lifecycle behavior.
- Do not create another pack/catalog/SDL/Compose schema, checksum helper,
  containment error, provider registry, validation pass, exception hierarchy,
  evidence repository, or lifecycle state machine.
- Do not delete generic core because identical historical source appears inside
  a pack archive; do not retain genuine scenario content because its bytes are
  not identical.
- Do not weaken the exact TechVault provider match to survive a pack update.
  New version/digest means new compatibility and qualification evidence.
- Do not test parity with `pip install -e`, a checkout-local SDL, an editable
  interaction plugin, ignored generated state, or a reduced local scenario.
- Do not expose the transient staged path in API output, logs, errors, run
  records, or user-facing catalog rows.
- Do not turn this cleanup into an unbounded lifecycle rewrite or delete an
  admitted component context before a replacement artifact is available.

## Non-Goals And Implementation Boundaries

This issue does not author or relocate TechVault, create packs for the curated
variants, select a future repository, make a `built` pack `golden`, define the
TechVault semantic verifier, redesign RAES/env-packs schemas, add remote
acquisition, introduce a plugin sandbox, or finish the LilRAE rename/migration.

It does not remove scenario-independent backend capability merely because
TechVault currently exercises it, and it does not promise a tiny-core dependency
split that the current env-packs packaging contract does not supply. Issues
#879, #883--#887, #915--#918, #934, #962, and #970 retain their separate
ownership.

The implementation boundary is: no active TechVault scenario-content copy in
APTL; no catalog/startup/distribution privilege for the nearby pack; one
validated acquired-bundle path for default, catalog, API, gates, and start;
identity-accurate evidence; and parity proof against the exact released pack
and packaged interaction provider, with unresolved golden and locked-input
limitations stated honestly.
