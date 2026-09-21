# Issue #880 TechVault Env-Pack Consumption Preflight

Reconciled against the current working tree on 2026-09-21. The supplied issue is
the contract; there is no Ground Control requirement. This is boundary guidance,
not an implementation plan or completion claim. TechVault already belongs in
`OpenRAE/env-packs`; do not move it again.

No new ADR is needed. Reuse accepted
[ADR-053](../adrs/adr-053-pack-backend-deployment-serving-interaction-seam.md),
[ADR-059](../adrs/adr-059-canonical-techvault-delivery-and-host-mcp-access.md),
and the [bundle-root](issue-874-scenario-bundle-realization-roots-preflight.md),
[content](issue-875-scenario-content-declaration-preflight.md), and
[fresh-start](issue-951-fresh-env-pack-start-preflight.md) boundaries. This note
replaces its older baseline and blanket prohibition on APTL-owned fixtures.
Related preflights [#970](issue-970-generic-lab-lifecycle-preflight.md),
[#980](issue-980-pack-adapter-install-seam-preflight.md), and
[#974](issue-974-shuffle-worker-docker-images-preflight.md) retain their broader
ownership; proposed work is not evidence of an implemented guarantee.

## Current Baseline And Residual Ownership Inventory

`pyproject.toml` and hashed runtime requirements pin `raes-env-packs==6.1.0`.
`aptl_techvault/runtime_parameters.py` and `tests/test_env_pack_bundle.py` bind
`techvault`, version `0.1.0`, to set digest
`sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b`.
These are repository pins, not fresh validation or live qualification results.
Do not carry forward this note's former 4.0.2 identity, maturity or input-closure
claims as facts about the new release.

Several mechanisms already exist: `core/scenario_catalog.py` projects the
env-packs catalog from a validated bundle; `resolve_scenario_selection()` keeps
catalog selection on the acquired route; the scenario API uses that projection;
`raes_repro._scenario_locator()` avoids a transient staged SDL locator; and
`_asset_manifest.ASSET_ROOTS` excludes `scenarios`. Preserve these incumbents.

This inventory names residual ownership decisions, not a claim that every listed
file is a duplicate or that matching names prove consumption:

| Surface / current evidence | Owner and guardrail |
| --- | --- |
| `scenarios/catalog.json`, TechVault SDL variants, `scenarios/archive/`, `participant-profiles/guided-purple-v1/` | APTL may retain explicit test/development fixtures and historical material. Name their consumer and purpose; exclude scenario fixtures from normal selection and default delivery. ADR-059 distinguishes the guided fixture from full TechVault. Fixtures must not satisfy missing acquired artifacts or serve as clean-package parity evidence. |
| Removed `config/wazuh_cluster/suricata_rules.xml` | The file is absent at final inspection and forbidden by the asset test. `wazuh_manager.conf` still includes that rule path. Verify that the admitted pack supplies the runtime rule; neither a dangling include nor a checkout fallback is acceptable. |
| `containers/mailserver/setup.sh`, mail domain/environment in `docker-compose.yml`, `containers/windows-victim/join-domain.ps1` | Remaining authored TechVault accounts/domain defaults need an explicit fixture/legacy-integration owner or removal from active distribution. Classify by runtime reachability, not just the word TechVault. |
| `scripts/{seed-prime,seed-shuffle,cortex-apikey,thehive-apikey,provision-range}.sh`, `config/{cortex,thehive}/` | Distinguish scenario seeds/configuration from backend/API integration. The installed startup provider selects project-relative seed/build scripts and image-specific config aliases. Retention requires an explicit input/output and mutation contract; replacing admitted pack content is not an integration exception. Workshop fixups remain historical/manual aids, never ordinary-start prerequisites. |
| `containers/generic-systemd-node22-base/Dockerfile` | The backend build now verifies the exact acquired pack and both source artifacts through `aptl_techvault.build_cache`, derives dependency-only manifests with lifecycle hooks omitted, and retains the npm cache and identity receipt. Source and staging inputs are removed from the image. Runtime content still uses admitted artifacts. |
| `src/aptl_techvault/` and `pyproject.toml` entry points | Existing APTL-owned integrations cover serving, startup, runtime parameters, planning compatibility, capture and verification. Their source may remain APTL-owned. This does not amend ADR-053’s separate-distribution requirement: the current bundled wheel differs from that decision. Preserve that packaging constraint in its own reconciliation; #880 neither claims a core-only artifact nor authorizes a packaging exception. Reuse exact compatibility and host-observed distribution provenance. |
| `core/lab.py` source-kind branches | `_load_selected_start_environment`, `_selected_start_steps`, `_selected_mcp_build_script`, `_mcp_startup_policy` and native ingress distinguish project-tree from env-pack behavior. Provenance must not authorize product preparation or skip declared requirements. Preserve explicit development compatibility without a privileged bundled-TechVault route. |
| Generated-artifact profiles, generic substrate, capture apparatus, MCP servers and backend materializers | APTL-owned mechanisms may remain, including exact named profile integrations selected through admitted typed requirements. Identical historical core/MCP source inside a pack archive does not transfer ownership of the maintained implementation. |
| `appliance/{inputs,input_profile,input_images,offline,payload_content}.py`, first boot and build/qualification scripts | Delivery consumes the same bundle, plus APTL-owned offline closure and policy. No appliance-only SDL copy, catalog alias, weaker validation or late substitution. Dependency/image/cache closure is distinct from pack identity. |

For each retained integration or fixture, its guidance/test must identify owner,
consumer, input authority and mutation/readback boundary. Hash comparison is
supporting evidence, not the ownership decision. Include renamed, generated and
archived copies in the inventory.

`tests/test_assets.py::test_real_repo_ships_no_techvault_scenario_content_copies`
checks the selected distribution and named forbidden duplicates. Preserve that
boundary rather than requiring all `scenarios/` or `participant-profiles/` files
to disappear. Necessary fixtures may remain; their presence must not authorize
runtime fallback. Consumption and distribution, not blanket absence, prove ownership.
`_asset_manifest.py` remains the single inventory for `hatch_build.py` and
`assets.materialize()`; no parallel packaging denylist. Inspect both importable
packages and the bundled `aptl/_labdata/src` copy.

## Architecture Decisions

### One verified bundle, one admitted execution

Nearby/bundled and separately acquired copies enter the same boundary:

`ScenarioSourceConfig -> resolve_scenario_bundle() -> env_pack_bundle() -> ScenarioBundle`

Catalog, CLI, API, static/live gates, participant delivery and start consume it.
Explicit contained project-tree development input remains distinct; it is never
an implicit fallback after pack/provider failure.

env-packs owns pack format, inventory, digests and catalog semantics. RAES owns
SDL parsing, instantiation, import locks, compilation and planning. APTL owns
acquisition and realization. Reuse `validate_pack()`,
`validate_pack_content_manifest()` and `resolve_pack_artifact()`; do not parse
`pack.yaml` independently, create a mirror schema, or replace `PackIdentity`
with an SDL hash. Installed-distribution trust is not publisher authenticity.
Remote acquisition and new trust policy are outside #880.

Carry the same bundle, instantiated scenario, `AdmittedScenarioStart`, execution
plan and cached `AptlRealization` through apply, retry, readback and run evidence.
Runtime flags belong to the existing exact-identity runtime parameter provider
**before** admission. Do not regenerate them on retry, edit staged SDL or patch
admitted content/config/image inputs to make boot pass. Keep bundle input,
operator `project_dir` and backend `realization_root` distinct.

### Backend integration cannot change scenario authority

Reuse `ScenarioStartupPlan`, fixed hooks, `PackBackendInteraction`, and the
existing service/startup policies. Core retains ordering, lifecycle locks,
timeouts, bounded retry, diagnostics and teardown. Exact providers supply their
validated contribution; no additional registry or event graph.

An image-specific mount alias, generated credential, native log producer or
readiness probe can realize admitted intent. Preserve declared output/consumer
identity, sensitivity and native observation obligations. Review
`aptl_techvault.startup.compose_service_policy()`: certificate aliases and the
project `config/thehive/application.conf` mount have different ownership claims.
A contained project path alone does not prove an authorized backend input.

Post-start seeding cannot become a second compiler or repair authored bytes
behind the admission record. Missing required realization is a failure; a soft
SOC warning cannot hide an unsatisfied admitted demand. Selected-provider reset
and resource receipts govern cleanup, not broadcasts to every installed provider
or a fresh default-pack selection.

## Cross-Cutting Layers And Canonical Incumbents

These are required passages, not assertions that every current call site already
meets them. Strengthen the existing owner where a gap is found.

| Layer / canonical owner | Required passage |
| --- | --- |
| HTTP authority: `api/deps.py`, session/BFF middleware, scenario/lab routers | Keep `verify_token`, Host/Origin/CSRF/session checks and server-owned project selection. No install endpoint, credential-bearing URL or client-selected executable. Participant and operator authority remain distinct. |
| Config/selector shapes: `core/config.py`, `scenario_catalog.py`, API schemas and web consumers | Preserve strict Pydantic `extra="forbid"`, safe identity/root validation, exclusive selectors and contained explicit paths. Catalog metadata is a presentation projection, not another manifest or arbitrary path union. |
| Acquisition/filesystem: `scenario_bundle.py`, env-packs gates, `utils/pathsafe.py` | Isolated singly linked staged bytes, bounded inputs, no traversal/special files or symlink escape, exact inventory/member/set verification and digest-bound reads. Direct `env_pack_bundle(source_pack=...)` callers cannot bypass ingress guarantees. |
| RAES admission: artifact availability, runtime parameters, `raes_planning_compat`, realization and manifest validation | Public RAES shapes, parameters, imports, artifacts, component specifications/locked inputs, topology, capture demands and policy pass before deployment effects. Compatibility remains bounded and pre-admission; it cannot suppress diagnostics or change a persisted plan. |
| Installed adapters: startup/runtime/capture/planning discovery, `pack_interaction_discovery`, verifier discovery | Preserve API/version/digest/backend checks as applicable, unique selection, validated immutable results, total component mappings and host-observed provenance. Installed Python is trusted code; contract checks are not a sandbox. |
| Operator secrets: `core/env.py`, credentials, `EnvVars`, startup alias/key validators | Operator `project_dir/.env`, hydration, placeholder rejection, valid names and explicit key allowlists remain canonical. Pack env cannot override secrets. No full environment/config passed to providers or seeds; preserve `DOCKER_TRANSPORT_KEYS` denial and backend transport projection. |
| Generated env delivery: `raes_stateful_realization`, `deployment/realization.py`, `_compose_stateful_artifact_helpers.py` | Preserve exact output/consumer/delivery shapes and exhaustive generator/profile dispatch. `artifact_environment_bindings()` checks outputs/names; `write_artifact_environment_files()` checks nonempty single-line values and writes private files. Flat env dictionaries or aliases cannot bypass this contract. |
| Effective deployment: `scenario_service_policy`, `scenario_startup_policy`, `_compose_stateful_model`, Compose model validation | Validate the fully merged model, including aliases, against independently admitted inputs. Preserve crypto/key-pair checks, canonical outputs, least-privilege mounts, ports, capabilities and native readback. Overrides cannot authorize themselves. |
| OS/backend authority: `DeploymentBackend`, Docker endpoint binding, ownership receipts, SSH and boundary enforcement | Fixed executables/argv, bounded execution/output, validated service/profile selectors, explicit transport and resource ownership. Secrets use existing stdin/private-file/header transports, never argv/logs. No host `shell=True`; guest scripts still require fixed commands and validated input. Preserve TLS/SSH trust and project isolation. |
| Orchestration children: `raes_runtime_orchestration`, backend realization and #974 contracts | Authored child images/socket intent are separate from host daemon authority. Pack paths/env cannot redirect Docker. A read-only socket is not restricted Docker authority; startup cannot silently change authored image identity. |
| Errors/observability: `EnvPackError`, `ScenarioError` subclasses, provider errors, RAES `Diagnostic`, `StartupDiagnostic`, `LabResult`, `get_logger`, `redact` | Use existing codes/results and bounded CLI/API messages. Log safe identity/provenance, phase, counts and timings; exclude raw parser/Pydantic input, subprocess output, env, secret prefixes and staging paths. No new exception hierarchy. |
| Persistence: `raes_repro`, `RunRecordInputs`, `backend_evidence.pack_interaction`, `LocalRunStore`, capture/content stores | Exact pack identity is separate from provider distribution/mapping and image identity. Reuse digests, secure atomic state and durable ownership; omit temporary roots and secret/generated bytes. Integrity, realization success, semantic verification and maturity remain distinct claims. |
| Distribution: `_asset_manifest`, Hatch, locks, appliance input/archive validation | One asset selection for checkout/wheel, pinned dependencies and verified offline closure. Wheel hash, artifact set digest, provider version and OCI digest answer different questions. No direct resource extraction as another runtime loader. |

### Concrete Security And Reliability Gaps To Catch

- `_stage_and_validate()` uses default link-following `shutil.copytree()` before
  validation. Checking resulting regular files does not prove source-link
  containment. Safe acquisition must precede copy; preserve legitimate installer
  hardlink-to-private-copy handling. Bound copy size/member count before disk
  exhaustion, not solely in the later validator.
- Bytecode exclusions accommodate installers; they do not authorize ignoring
  arbitrary unknown members. Preserve exact inventory validation and digest-bound
  reads against mutation between admission and use.
- `_sweep_stale_stagings()` assumes an hour-old tree cannot be active. Long
  startup/observation and concurrent runs can outlive that assumption. Retain
  inputs for their consuming operation; age is not ownership or safe cleanup
  evidence. Reuse lifecycle ownership, not a new pack database.
- Pack/catalog errors can interpolate raw text or paths; `redact(str(exc))`
  does not guarantee path removal. The list API logs failures and returns an
  empty list. That is not successful acquisition; start must still fail closed.
- Seed helpers contain credential defaults and secret-prefix output. Retained
  integrations must satisfy the secret/transport contracts above. Python
  redaction cannot undo exposure through argv, child output or direct invocation.
- Config aliases need no-follow, ownership-checked access. A successful
  `.resolve().is_relative_to()` check is not the existing no-follow contract
  and does not bind the file opened later. Do not weaken `pathsafe` to match it.

## Extensibility And Whole-Repository Boundary

The seam is the existing source selector returning `ScenarioBundle` with exact
`PackIdentity`, plus backend identity for purpose-specific adapter selection.
Another release, installed location or offline copy should change data/providers,
not core enums, config fields, API DTOs or Compose special cases. Future
acquisition belongs behind the resolver and upstream policy, not a new downloader.
Build-cache preparation must consume verified artifacts and target runtime
parameters instead of a TechVault path in a generic Dockerfile; this does not
require a generic build/plugin framework.

Scope crosses CLI/API/web projection; config/env; staging; RAES/backend admission;
generated Compose, certificates/content; Docker/SSH/host exposure; startup,
seed, retry, readiness, reset and teardown; capture/verification/run persistence;
fixtures/scripts/config/containers; wheel/dependency packaging; participant and
appliance first boot/offline inputs; and CI/release qualification.

## Regression And Evidence Guardrails

Extend existing catalog/API, `test_env_pack_bundle`, bundle wiring/root,
`test_pack_content_resolution`, `test_env_pack_realization`, startup adapter,
runtime-parameter, installed-adapter and asset/wheel tests. Default, catalog and
API selection must identify the same pack regardless of staging location.
Exercise missing/corrupt/extra members, link escapes, malformed selectors,
provider mismatch, concurrent/long-lived staging, safe errors and unchanged
admitted execution on retry. Local decoys must never satisfy acquired-pack
failure. Do not freeze today's filenames or prohibit permitted fixtures.

#880 owns uniform-loading regressions and clear ownership. **#870 owns the
clean-package parity proof**: installed non-editable artifacts, no checkout or
`PYTHONPATH` assistance, acquired full TechVault through public start, compatible
packaged adapters, no manual fixups/post-admission substitutions, native
content/service readback and teardown. Bind evidence to exact pack/provider,
runtime/dependency/image/platform versions; disclose closure and maturity
limitations. Static validation, mocks, reduced fixtures and container health
cannot replace it. No live proof was run in this preflight.

Reuse `.ground-control.yaml`, `.gc/plan-rules.md`, `.github/workflows/checks.yml`
and `.pre-commit-config.yaml`. Python changes require relevant pytest coverage;
changed MCP common requires dependent builds/tests. Deployment asset changes
require clean fresh-machine `aptl lab stop -v && aptl lab start`. Run required
pre-commit checks; report existing failures/merges without treating them as
completion or permission to expand scope.

## Non-Goals And Anti-Patterns

No implementation here; no pack move, repository-wide relocation, generic plugin
infrastructure, broad #970 decomposition, RAES/env-packs schema fork, duplicate
validators/errors/persistence, remote acquisition or new auth surface. No
identifier purging, tiny-core dependency split, curated pack authoring, golden
certification or appliance qualification.

Avoid source/name-based startup privilege, editable-install parity claims,
checkout fallbacks, prebuilt-image content masquerading as admitted artifacts,
late script/config/image replacement, broadened digest matching, fixture deletion
as an ownership shortcut, and paths treated as identity. Necessary fixtures and
backend integrations may remain APTL-owned; none may become a hidden second
TechVault content authority.

## Implementation ownership and verification contract

| Retained input | Owner / consumer | Authority and permitted effects |
| --- | --- | --- |
| `scenarios/*.sdl.yaml`, `scenarios/catalog.json`, `participant-profiles/guided-purple-v1` | APTL research fixtures; variant, participant and paper tests | Explicit development paths and digest-bound research profiles only. Excluded from the normal acquired catalog and wheel asset inventory. `scenarios/archive` is historical reference. |
| `src/aptl_techvault`, `config/cortex`, `config/thehive`, `scripts/seed-prime.sh` and its helpers | APTL backend integrations selected by the exact compatible startup provider | Consume admitted services and generated credentials; initialize native service API state and observe required identities. Certificate aliases reuse generated outputs; the image-specific TheHive configuration connects those outputs to its native service. No SDL, content, image or container replacement. Credentials use stdin/private files; provisioners return keys to their caller without logging prefixes. |
| `containers/mailserver/setup.sh`, `containers/windows-victim/join-domain.ps1`, legacy Compose domain defaults | APTL legacy backend/development fixtures | Used only by explicit legacy profile selection; not sources for acquired TechVault's authored accounts, domains or content. The ordinary full pack realizes its own declared bytes. |
| `containers/generic-systemd-node22-base/Dockerfile`, `aptl_techvault.build_cache` | APTL offline backend build integration | Acquire and validate the exact compatible pack, resolve both MCP source artifact identities, and read only their package manifests and lockfiles. Retain npm dependency cache and pack identity evidence. Discard extracted manifests and build tools; runtime MCP source still comes from admitted artifacts. |
| `containers/suricata-wazuh-agent/Dockerfile` | APTL product image integration | Combine only product rules shipped by the pinned upstream image into its built-in ruleset during image build. No network rule update or scenario rules enter this image; the admitted pack still supplies its configuration and local rules. |
| Generic substrates, capture apparatus, MCP sources and materializers | APTL backend | Selected admitted runtime requirements and existing provider contracts govern realization; no checkout content may satisfy a missing pack artifact. |

The duplicate DB seeds, DNS/fileshare configuration, vulnerable web application,
and scenario-specific Wazuh rule/decoder/integration copies are removed from the
runtime asset inventory and legacy Compose mounts. The acquired artifact set
owns their current versions. Readback must observe those declared runtime paths,
including Wazuh's rule includes.

Source acquisition copies only bounded regular files through no-follow handles,
then applies upstream inventory and digest validation. Installer hardlinks become
private copies. Another acquisition never deletes a runtime bundle based on age;
retain runtime inputs until the owning lab is torn down and its project state is
explicitly discarded. Read-only CLI/API catalog views remove only their own
fresh staging after projection, including failed detail lookups. Invalid source
selectors and acquisition failures remain bounded and do not expose source paths.

Uniform-loading and installed artifact tests belong to #880. Full clean-package
release parity, including discovery, attack, telemetry, triage and MCP actions,
remains #870's acceptance evidence; this cleanup does not claim that proof from
static tests or a successful image build.
