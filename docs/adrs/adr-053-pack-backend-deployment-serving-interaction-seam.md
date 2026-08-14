# ADR-053: Pack-Backend Deployment-Serving Interaction Seam

## Status

accepted

## Date

2026-08-10

## Context

APTL can now realize an environment pack from declared RAES desired state and
the APTL backend manifest, as required by
[ADR-051](adr-051-component-level-raes-realization.md). The environment-pack
cutover exposed one configuration class that neither authority owns:
component membership in operator-facing groups such as `soc`, `enterprise`,
`wazuh`, `victim`, and `kali`.

This grouping is not portable scenario content. RAES `Node` is a closed model,
and its `roles` field describes local identity rather than backend operator
packaging. It is also not a general APTL rule. The grouping names components in
one pack and operator controls in one backend. The same pack could be served by
a backend with different controls, and APTL must be able to serve another pack
without learning its component names.

Issue #875 temporarily placed the TechVault/APTL grouping in
`src/aptl/backends/_component_profiles.py`. The table is deliberately marked as
operator packaging, not realization, but it is queried independently while the
RAES plan is interpreted and while generated Compose is rendered. Leaving the
table there would make pack knowledge part of core and let the two lookups
drift.

APTL already has a precedent for scenario-and-backend glue:
[the issue #878 scenario-verification seam](../architecture/issue-878-scenario-verification-plugin-seam-preflight.md)
uses Python distribution entry points, records host-observed package
provenance, and keeps scenario adapters out of the core distribution. The
pack-backend seam uses the same installed-extension mechanism, but it has a
different, intentionally smaller contract. It returns inert serving data and
receives no operations surface.

Three authorities must remain distinct:

| Concern | Authority |
| --- | --- |
| Scenario nodes, artifacts, content, topology, runtime configuration, dependencies, and acceptance criteria | RAES SDL, compiler, planner, and runtime contracts |
| Artifact admission, component realization, backend effects, and read-after-write proof | APTL's RAES adapters, backend manifest, typed realization objects, and `DeploymentBackend` |
| How one validated pack's already-admitted components are labelled for one backend's operator controls | One installed pack-backend interaction provider, or the pack-agnostic core default |

## Decision

### Use one installed, provider-agnostic extension contract

APTL discovers interaction providers with Python distribution entry points in
one dedicated group, `aptl.pack_backend_interactions`. The `aptl-labs`
distribution registers and bundles no pack-specific provider. A provider for
TechVault/APTL is a separately installed distribution maintained alongside the
pack release or in another out-of-tree integration package.

Discovery uses installed distribution metadata only. The entry-point name is a
documented selector composed from the exact pack id and backend target id. This
lets core ignore providers for other installed pack/backend pairs without
importing them; pack version, set digest, backend version/profile, and optional
transport are then checked on the loaded typed provider. Scenario data, pack
files, `aptl.json`, environment variables, CLI arguments, the current
directory, and participant profiles never provide a module, class, path, URL,
command, or import string.

Core resolves a provider only after all of the following exist:

- a pack admitted by `validate_pack()` and
  `validate_pack_content_manifest()`;
- a canonical pack identity containing the validated pack id, pack version,
  and associated-artifact set digest;
- the backend target identity from `create_aptl_manifest()` and the existing
  APTL target name/version/profile contract; and
- the immutable component-address inventory produced by the one admitted RAES
  provisioning plan.

Pack identity is not scenario identity. A pack can contain more than one
scenario, and two pack revisions can expose the same scenario name. The
pack-backed `ScenarioBundle` must carry identity returned by the env-packs
public validation surface. APTL must not reparse pack metadata, derive identity
from a directory name, use a staging path as identity, or duplicate the
env-packs schema. Project-tree bundles have no pack identity and continue to use
their existing Compose index during the legacy transition.

Backend identity is also not `DeploymentConfig.provider`. The canonical
identity is the RAES target name, target version, and capability profile;
`docker-compose` versus `ssh-compose` is a transport fact that is included only
when a provider explicitly constrains transport. The neutral backend-identity
value already used by scenario verification must be reused or moved to a
neutral module and re-exported. A second backend identity DTO is prohibited.

### Keep the contract data-only and closed

The provider receives an immutable context containing only:

- the validated pack identity;
- the canonical backend identity and optional deployment transport;
- sorted canonical RAES component addresses already present in the admitted
  provisioning plan; and
- the backend-owned, closed vocabulary of supported operator groups.

It does not receive a scenario model, `ProvisioningPlan`, `AptlRealization`,
`DeploymentRealizationSpec`, `DeploymentBackend`, `AptlConfig`, `EnvVars`,
process environment, filesystem path, run store, logger, subprocess helper, or
network client.

The versioned result contains one typed field: a total mapping from each input
component address to a finite set of operator-group labels. The provider cannot
return component definitions, service names, images, build instructions,
artifacts, content, runtime configuration, environment bindings, commands,
mounts, networks, ports, health checks, dependencies, paths, URLs, credentials,
or arbitrary extension data.

Core validates the result before any backend mutation:

- extension API version, provider id, pack identity, and backend compatibility
  match exactly;
- exactly one compatible installed provider may claim the pack/backend pair;
- mapping keys equal the admitted component-address inventory, with no missing,
  extra, duplicate, alias, normalized, or display-name keys;
- every group is a bounded string from the backend's canonical supported-group
  vocabulary; and
- the result is copied into core-owned immutable values before use.

A compatible provider that fails to load, raises, returns a malformed result,
or conflicts with another compatible provider is a pre-mutation error. Core
does not pick the first provider, merge providers, or fall back after a broken
claim.

When no entry point claims the exact pack identity, core uses the pack-agnostic
default. The default returns every admitted component with an empty group set.
For generated Compose this means that the admitted component is unprofiled and
therefore starts with the admitted scenario; it does not infer a group from the
component name. An installed provider must use an explicit empty set for a
component that is deliberately always active. Total coverage makes a stale
provider fail when a pack adds or removes a component instead of silently
misclassifying it.

### Resolve serving intent once, after planning

RAES planning and component lowering complete without an interaction provider.
Core then joins the validated provider result to the admitted component
addresses exactly once. That one resolved value drives both:

- intersection with `ContainerSettings.enabled_profiles()` plus core profiles
  through the existing `public_start_profiles()` /
  `select_backend_profiles()` workflow; and
- the per-service `profiles` labels emitted by generated Compose.

Group selection is a pre-mutation admission policy, not permission to apply a
partial RAES plan. Every admitted component must either be deliberately
ungrouped or have at least one membership enabled by the operator. If not, core
returns a stable diagnostic before any image-free materializer or Compose step
runs. Core never removes the disabled component from the plan or reports the
remaining subset as a successful realization. This is required across pinned
image, component-build, and dynamic-composition routes; checking only Compose
services would let image-free components bypass the serving policy.

The renderer must consume the resolved typed value. It must not rediscover a
provider or query a name table. The interim `_component_profiles.py` lookup is
removed after the external TechVault/APTL provider is available. The legacy
`ComposeProfileIndex` remains the source for a project-tree bundle that still
ships `docker-compose.yml`; it is not copied into the new contract.

`explicit_compose_profile_hints()` is not an alternate authority. Backend
profile hints do not belong in RAES payloads, and the strict RAES model does not
admit them. The migration must remove that dead path or quarantine it to a
documented legacy input that cannot be reached by an environment pack.

The operator-profile vocabulary currently has several views:
`ContainerSettings` fields, `CORE_PROFILES`, `ALL_KNOWN_PROFILES`, the static
Compose file, and the interim component table. The implementation must not add
another copied allowlist. The supported vocabulary and the enabled subset need
one canonical owner adjacent to `public_start_profiles()`; start, stop, kill,
provider-result validation, and Compose argv construction consume that owner.
The special `web` lifecycle must remain explicit rather than becoming accepted
accidentally because one copied list happens to contain it.

### Enforce the non-realization invariant structurally

The interaction result may only label or select components already present in
the admitted plan. Applying it must leave all non-serving projections unchanged:
node and service identity, source route, image/build identity, runtime desired
state, artifact/content placement, generated artifacts, accounts, persistence,
topology, ACLs, dependencies, published ports, and observation requirements.

The provider is never passed to `RuntimeManager.plan()`, artifact availability,
`interpret_provisioning_plan()`, materializers, image resolution, stateful
providers, observation, or `DeploymentBackend`. It cannot add a component to a
deployment spec or suppress RAES readback. A component whose only memberships
are disabled blocks before mutation; core does not start a partial graph and
wait for observation to discover the omission. The existing observation and
RAES non-approximation gates remain the final proof that every admitted resource
was realized.

Conformance tests must compare the realization before and after serving intent
is attached and prove that only group-label fields differ. Tests must also prove
that generated Compose contains only services derived from the RAES realization
and that provider-supplied keys cannot create a service.

Python entry points are discovery, not isolation. Importing an installed Python
distribution executes code with the APTL process's authority. The contract
withholds effectful objects and makes provider output inert, but it cannot
contain a malicious package that deliberately imports unrelated APIs. Provider
installation therefore remains an explicit trusted package-management action.
If hostile provider code must be supported, this decision is insufficient; a
separate out-of-process sandbox, authenticated protocol, and resource policy are
required.

### Reuse existing validation, failure, logging, and evidence surfaces

Expected provider and result failures become stable
`raes_contracts.diagnostics.Diagnostic` errors through
`aptl.backends.raes_diagnostics.diagnostic()`. They flow through the existing
`ApplyResult`, `render_raes_diagnostics()`, `LabResult`, CLI, and API envelopes.
No public plugin exception hierarchy, result-like exception, readiness state,
or fallback workflow is introduced. Raw import exceptions, tracebacks, entry
point targets, host paths, or provider-returned text never enter an operator
error.

Use `get_logger()` and `redact()` at the discovery boundary. Logs contain the
host-observed distribution name/version, entry-point name, stage, stable
outcome code, duration, and bounded counts. They do not contain a full context
or result, raw exceptions, pack paths, environment/config values, Compose
stderr, or serialized realization data.

The run record's existing `backend_evidence` section remains the persistence
owner. It records the validated pack identity, extension API version,
host-observed provider distribution/version and entry-point id, a deterministic
digest of the normalized component-to-group result, and the already-recorded
selected profiles. The digest reuses the RFC 8785, domain-separated
`aptl.core.provenance.identity.derive_identity()` primitive with a code-owned
serving domain; it is not another JSON hashing helper. Plugin metadata must not
be written under RAES realization state, used as portable scenario identity, or
stored through a new repository. Structured writes continue through
`LocalRunStore` redaction boundaries.

The change adds no HTTP, SSE, WebSocket, MCP, or participant surface. Any future
API projection remains behind `verify_token`, `WebAuthSettings`, and
`BFFMiddleware`, uses strict Pydantic response models, and returns only bounded
host-observed metadata. It must never expose provider objects or accept install
or import controls.

## Cross-Cutting Incumbents

| Concern | Canonical incumbent and required reuse |
| --- | --- |
| Pack acquisition and validation | `ScenarioSourceConfig`, `resolve_scenario_bundle()`, `env_pack_bundle()`, `ScenarioBundle`, env-packs `validate_pack()` / `validate_pack_content_manifest()`, and `aptl.utils.pathsafe`. The seam consumes validated identity and never reads pack files. |
| Scenario and realization authority | `raes.parse_sdl_file`, `RuntimeManager.plan()`, planner diagnostics, `AptlProvisioner`, `interpret_provisioning_plan()`, `AptlRealization`, `DeploymentRealizationSpec`, RAES observation, and the SEM-218 non-approximation gate. No schema or workflow is mirrored. |
| Backend identity and effects | `APTL_RAES_TARGET_NAME`, `APTL_RAES_TARGET_VERSION`, `create_aptl_manifest()`, `create_aptl_runtime_target()`, and `DeploymentBackend`. Reuse the existing neutralizable `BackendIdentity`; do not identify a backend by a class name or config provider alone. |
| Operator profile policy | `ContainerSettings.enabled_profiles()`, `CORE_PROFILES`, `public_start_profiles()`, `select_backend_profiles()`, and the backend Compose-profile vocabulary. Consolidate current copied name lists instead of adding another. |
| Legacy Compose binding | `load_compose_profile_index()`, `ComposeProfileIndex`, dependency-closure checks, effective Compose validation, and the static `docker-compose.yml` during its remaining project-tree lifetime. |
| Generated deployment model | `DeploymentNodeRealization`, `render_realization_compose()`, `base_compose_file()`, effective model validation, and `DockerComposeBackend._build_command()`. Resolve membership once and pass it through typed data. |
| Errors and logs | RAES `Diagnostic`, `aptl.backends.raes_diagnostics.diagnostic()` / `render_raes_diagnostics()`, `ApplyResult`, `LabResult`, `get_logger()`, and `redact()`. |
| Persistence and provenance | `RunRecordInputs`, `build_reproducibility_record()`, the `backend_evidence` namespace, `aptl.core.provenance.identity.derive_identity()`, `LocalRunStore`, and existing run-id/path/redaction rules. |
| Packaging and supply chain | `pyproject.toml`, `uv.lock`, hashed requirements, Hatch package boundaries, `_asset_manifest.py`, and the core-wheel tests. Core registers and bundles zero pack-specific providers. |
| Quality workflow | Focused pytest seam, realization, renderer, config, run-record, and packaging tests; the fast suite; the TechVault static gate where backend/manifest behavior changes; Ruff complexity; `pre-commit run --all-files`; and CI/Sonar. Compose, Dockerfile, or `config/` edits still trigger the clean-lab gate in `.gc/plan-rules.md`. |

## Security And Host-Layer Passage

| Layer | Required behavior |
| --- | --- |
| Config shape | `AptlConfig` remains `extra="forbid"`. No plugin selector, module path, import name, command, URL, credential, or arbitrary options map is added to `aptl.json`. |
| Pack shape and path containment | Discovery happens only after env-packs' bounded layout/content validation and APTL's contained staging. Provider matching uses validated identity, never an authored path or directory name. |
| RAES shape, planner, and policy gates | The same parsed scenario and admitted provisioning plan produce the component inventory. Provider output is not planner input and cannot alter demand, availability, backend capabilities, or satisfaction. |
| Extension shape | Exact API/pack/backend matching, one provider, total component coverage, closed group values, bounded counts/strings, immutable copying, and no arbitrary data. Malformed or ambiguous installed claims fail before mutation. |
| Secret and environment binding | The provider receives no `AptlConfig`, `EnvVars`, `.env`, generated config, credentials, tokens, keys, or backend operation surface. The operator `.env` remains bound by the existing Compose command path. |
| OS and process exposure | A validated group may reach `docker compose --profile` only as one element in the existing argv list. It never becomes an executable, option name, shell fragment, environment variable, path, URL, or stdin payload. No `shell=True` or plugin-controlled subprocess is added. |
| Backend and host effects | All Docker, Compose, SSH, file, image, network, and container operations stay behind `DeploymentBackend`. The provider is resolved and discarded before that boundary; only validated labels cross it. |
| Error envelope | Stable diagnostic codes and bounded core-authored messages flow through existing result envelopes. No raw exception, provider text, pack path, import target, command, environment, or backend stderr is exposed. |
| Logging, OTel, and persistence | Record identities, versions, mapping digest, stages, counts, and selected groups only. Shared redaction remains mandatory, and no provider context/result is attached wholesale to logs, spans, run records, or exports. |
| API and auth | No new route exists. A later read-only projection uses the existing bearer/session, Host, CSRF, strict-schema, and loopback exposure gates and cannot mutate installation or selection. |

## Consequences

### Positive

- APTL core can serve new packs without acquiring their component names.
- RAES and ADR-051 remain the only realization authority.
- The current operator toggles retain pack-specific behavior through a
  separately installed `aptl-techvault-pack-interaction` provider.
- A stale or ambiguous installed provider fails before deployment instead of
  silently changing which component a toggle selects.
- One resolved mapping feeds selection, rendering, evidence, and diagnostics,
  eliminating the current double lookup.

### Negative

- The default provider cannot preserve pack-specific toggle behavior; it starts
  admitted components without inferred grouping.
- The separately released pack/backend provider must be installed and versioned
  with the pack integration it supports.
- Installed Python providers remain trusted code despite the deliberately inert
  interface.
- Pack and provider provenance becomes another backend-evidence input that run
  records must retain.

### Risks

- If component identity is normalized or reduced to a terminal name, two nodes
  can alias and receive the wrong group. Exact RAES addresses avoid this.
- If provider discovery runs before pack validation or planning, an extension
  can become a hidden input to realization. Ordering and differential tests are
  required guardrails.
- If a renderer or dependency helper performs its own lookup, selection and
  generated Compose can disagree.
- If serving admission checks only Compose-managed nodes, a disabled
  dynamic-composition component can still be materialized before Compose starts.
- If the supported group vocabulary remains duplicated, a provider value can
  be accepted by one lifecycle path and ignored by another.
- If provider provenance is omitted from run evidence, two apparently identical
  runs can have different serving behavior without an audit trail.

## Extensibility

The selection key is:

`(extension API version, validated pack identity + version + set digest,
backend target identity + version + profile, optional transport)`.

The data key is the exact admitted RAES component address. A new pack revision
can reuse a provider only when the provider returns total valid coverage for
that revision's component inventory. A second backend adds another installed
provider and backend-owned group vocabulary; it does not add a pack branch to
core.

The result envelope is versioned, but it is not an untyped plugin property bag.
The next deployment-serving concern must receive its own typed, bounded field
and invariant review. Adding one must not change RAES demand or any
`DeploymentRealizationSpec` effect. Executable hooks, generic callbacks,
provider-owned validation functions, and arbitrary backend configuration are
not extensibility mechanisms for this seam.

## Anti-Patterns

- Moving `_COMPONENT_PROFILE` into another `src/aptl` file and calling it a
  plugin.
- Shipping a built-in TechVault fallback, example provider, disabled provider,
  or test provider in the `aptl-labs` distribution.
- Selecting providers by scenario name, filename, staging path, current
  directory, config field, environment variable, module string, or first-found
  order.
- Reusing scenario verification's runner/report contract or building a generic
  plugin lifecycle. This seam returns inert serving data and has different
  absence/failure semantics.
- Treating `DeploymentConfig.provider` as backend identity or treating a pack id
  as scenario content identity.
- Passing a backend, materializer, subprocess runner, path, environment, config,
  or run store to a provider.
- Letting a provider supply services, dependencies, Compose fragments, image
  overrides, Docker labels, commands, environment entries, mounts, ports,
  health checks, or generated files.
- Querying provider discovery from both plan interpretation and Compose
  rendering, or merging plugin values with SDL `compose_profile` hints.
- Normalizing component addresses, accepting partial mappings, ignoring unknown
  groups, merging duplicate providers, or silently defaulting after a matching
  provider breaks.
- Persisting provider data as RAES realization state or exposing raw plugin
  failures through CLI/API/logging.

## Non-Goals

- No artifact acquisition, materialization, image build/pull, content injection,
  node realization, topology change, runtime configuration, dependency
  resolution, or observation policy moves out of core.
- No SDL, RAES contract, environment-pack format, backend-manifest capability,
  participant contract, MCP protocol, or deployment-backend effect API is
  redesigned.
- No plugin installation, auto-download, dependency resolver, marketplace,
  remote update, or pack-controlled import mechanism is added.
- No untrusted-code sandbox, process isolation, IPC protocol, or plugin-specific
  secret store is provided.
- No HTTP/UI management surface or operator-editable plugin configuration is
  added.
- No generic extension framework or arbitrary serving-policy language is
  introduced.

## References

- [ADR-005](adr-005-docker-compose-profiles.md): current operator profile
  lifecycle.
- [ADR-025](adr-025-strict-first-party-config-schema.md): strict durable config
  boundary.
- [ADR-029](adr-029-control-plane-secret-handling.md): secret and persistence
  redaction boundary.
- [ADR-037](adr-037-docker-compose-backend-cohesion.md): Compose effects remain
  behind the backend.
- [ADR-044](adr-044-raes-aligned-run-reproducibility-record.md): backend evidence
  and run-record ownership.
- [ADR-046](adr-046-dynamic-raes-scenario-realization.md) and
  [ADR-051](adr-051-component-level-raes-realization.md): RAES realization
  authority.
- GitHub issue #875: environment-pack cutover and interim profile table.
- GitHub issue #895: pack-backend interaction seam.
