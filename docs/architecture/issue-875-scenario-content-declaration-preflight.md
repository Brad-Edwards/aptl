# Issue #875 Scenario Content Declaration Preflight

This note fixes the repository-wide boundary for removing engine-checkout paths
from the TechVault SDL. It is architecture guidance, not an implementation
plan. [ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md) remains
the dynamic-realization authority; [ADR-047](../adrs/adr-047-raes-experiment-admission-and-trial-plan-boundary.md)
owns authorized artifact resolution; [ADR-051](../adrs/adr-051-component-level-raes-realization.md)
owns component versus scenario-content boundaries; and
[the issue #874 preflight](issue-874-scenario-bundle-realization-roots-preflight.md)
owns realization-root propagation.

## Architecture Decisions

### Declare identity and destination, never an engine location

There are three distinct inputs and they must remain distinct:

| Input | Canonical carrier | Boundary |
| --- | --- | --- |
| Scenario-supplied bytes | RAES `Content` whose `Source` carries an exact `ArtifactRequirement` satisfied from a validated environment pack | `source.name` is an opaque artifact id. The exact identity supplies version, SHA-256 digest, and media type; `path`/`destination` is the absolute in-range destination. No checkout, pack-relative, generated-state, or host path is authored as source semantics. |
| Component software and invariant startup mechanics | Existing RAES source-artifact mechanisms and ADR-051 component artifacts | Application source trees, Python packaging files, Kali capture tooling, and reusable flag-generator mechanics are software/build inputs, not planted content. They must not be converted into a large list of content files merely to remove paths. |
| Standup-produced material | RAES `GeneratedArtifact` lowered through the existing typed stateful realization graph | Pivot key material, authorized-key projections, the SOC CA/service certificates, and other run-produced bytes are generated artifacts with declared outputs, sensitivity, lifecycle, dependencies, and least-privilege consumers. They are neither pack files nor ordinary content. |

Inline text remains valid for small, genuinely authored text. It is not a
substitute for binary assets, source trees, or secret-bearing generated output.
A directory name is not an inventory: every planted file must have an authored
destination and exact artifact identity, or use a portable exact
service-materialization contract that owns the complete item set. The
materializer must never walk, glob, archive-copy, or recursively copy an
undeclared source directory.

The canonical portable source is a RAES environment pack. Ingress must run both
of the companion package's public gates:

- `validate_pack()` for the bounded pack layout, metadata, SDL, and structured
  diagnostics; and
- `validate_pack_content_manifest()` for the RAES associated-artifact parent,
  exact inventory, set digest, per-artifact size/checksum, and byte binding.

That content-manifest gate already rejects missing and extra members, symlinks,
special files, hardlinks, escaping/non-canonical locators, and a file set that
changes during validation. APTL must consume it, not create a second inventory,
checksum, URI, or pack-validation schema.

The current `raes-env-packs` public API returns the validated manifest but does
not expose its validated opaque-artifact-id-to-byte resolution as a public
consumer API. The package must first expose a bounded, single-open result
carrying the canonical artifact identity and immutable bytes. APTL must not
import `raes_env_packs.digest` private helpers, parse
`raes-environment-pack:` URIs itself, or reopen a manifest path after
validation. The companion package also owns the canonical projection from an
associated-artifact descriptor and pack version to RAES `ArtifactIdentity`;
APTL must not choose that version rule locally. This is a hard prerequisite,
not a reason to fall back to paths.

### Enforce exactness at every boundary

“Declared” is insufficient unless the same identity survives ingress,
planning, materialization, and readback:

1. The pack manifest proves the exact input byte set.
2. `Source.artifact_requirement`, `ArtifactAvailabilityContext`, the manifest's
   artifact mechanism, RAES planner diagnostics, and artifact-satisfaction
   disclosure prove that the planned content address selected those bytes.
   The pack route is a digest-bound mechanism with the exact joined
   `copy`/`pack-ingestion` route, not the OCI pull profile and not ambient
   local lookup.
3. Existing typed content realization carries the admitted artifact identity
   and immutable bytes to `DeploymentBackend`; it does not carry
   `project-file`, `project-directory`, or a relative host locator.
4. Read-after-write verifies destination kind and bytes against the admitted
   digest. Existence-only `observe_file()` and content-type-only SEM-218
   observation do not satisfy the issue.
5. Exact owned sets reject undeclared collisions and stale members. For named
   or retained services such as the fileshare, reuse RAES
   `service-content-v1` (`ensure-owned-items`,
   `reject-unowned-collision`, `canonical-content-digest`) and its independent
   daemon/guest readback. APTL may advertise that profile only after execution,
   readback, snapshot evidence, and conformance all exist.

Exactness is scoped to declared items and explicit ownership roots. It does not
make every base-image or operating-system file scenario-owned. Where RAES
cannot express an exact owned filesystem set outside a named service, that is
an upstream contract gap; do not add an APTL directory-manifest DTO or infer a
root from common destination prefixes.

Generated artifacts follow the same rule. Each artifact gets an isolated,
canonical, owner-only staging root; its complete declared output set is
validated before consumers start, and unexpected outputs in that owned root
fail. Consumers receive only their declared outputs, read-only, with exact
mount-source/destination readback. The existing certificate chain/key/SAN and
permission validators remain mandatory; SSH providers additionally verify key
pairs, authorized-key membership/order, file modes, and consumer isolation
without disclosing key bytes.

Current RAES exposes only `certificate_bundle` and `rendered_config`.
`certificate_bundle` is valid for the SOC X.509 material but must not be
misused for SSH keys. A portable SSH key/access-bundle generated-artifact kind
must land upstream before APTL claims it. RAES also needs to express
producer-private state or output-level consumer selection if one generated
bundle would otherwise expose the SOC CA private key or every SSH private key
to every consumer. Until then, use separately isolated least-privilege
artifacts where the current model can express them and treat the remaining
shape as blocked; never distribute a broad shared bundle.

### Preserve one admitted execution and the existing owners

Scenario-dependent producers run only after one successful parse/compile/plan
admission and before their consumers mutate or start. Bind-mount preflight,
producer dispatch, backend application, observation, retry, and run evidence
must consume that same execution identity and typed realization.
`_load_stateful_artifact_ownership()` currently performs a separate planning
pass before the actual start; it must not become the template for SSH/SOC
generation or a third workflow. Ownership is projected from the admitted plan.

The operator's `~/.ssh/aptl_lab_key` remains a control-plane credential owned
by `aptl.core.ssh` and never enters SDL or pack identity. Only the public
authorization projection that is deliberately planted into a node is part of
the scenario generated-artifact graph. Kali/workstation pivot private keys and
their public/authorized-key derivatives are scenario artifacts. The existing
`ensure_pivot_key()`, `ensure_workstation_pivot_key()`, authorized-key
builders, and permission hardening are provider incumbents; they are invoked
through declared artifacts rather than unconditionally for every lab.

`ensure_soc_certs()` and `SOC_SERVICE_REGISTRY` remain the SOC CA provider and
extension seam. The provider's secure directory containment, atomic writes,
modes, expiry/chain/key/SAN validation, and reuse policy are retained. Config
profile flags no longer decide whether the scenario requires these bytes; the
admitted generated-artifact graph does. Producer-private CA state stays out of
consumer mounts, snapshots, logs, packages, and SDL.

Generated-artifact dispatch must be exhaustive and fail closed. The current
“certificate bundle, otherwise rendered config” branch is unsafe when a third
kind appears. Extend the existing typed stateful graph with an explicit
generator/profile-to-provider dispatch and reject an unsupported pair before
any producer runs. `provenance` must be a portable, non-secret producer/profile
identity, not `config/...` or another host locator; if the upstream field is
not sufficiently typed, fix that contract instead of overloading a free-form
path.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| SDL shape and semantics | RAES `Content`, `Source`, `ArtifactRequirement`, `GeneratedArtifact`, stateful consumers, service materialization, parser, semantic validator, compiler, planner, and `CompiledRealizationRequirement`. No APTL SDL mirror. |
| Pack format and byte identity | The exactly pinned `raes-env-packs` package, `validate_pack()`, `validate_pack_content_manifest()`, and RAES associated-artifact models/validators. Do not vendor schemas or private URI logic. |
| Artifact admission and proof | `aptl_artifact_mechanisms()`, `artifact_availability_for_scenario()`, `ArtifactAvailabilityContext`, planner artifact diagnostics, and `ArtifactSatisfactionDisclosureModel`. Add a pack-ingestion profile beside, not inside, the OCI/build profiles. |
| Bundle/root authority | `ScenarioBundle`, a new validated pack-backed resolver at the issue #874 seam, and `aptl.utils.pathsafe` no-follow primitives. `ScenarioBundle.details()` continues to omit operational roots. |
| Interpretation and deployment | `interpret_provisioning_plan()`, `AptlRealization`, `DeploymentContentRealization`, `DeploymentGeneratedArtifactRealization`, `DeploymentRealizationSpec`, and `DeploymentBackend`. Replace obsolete project-path variants; do not add a parallel content plan. |
| Content effects and readback | The generic materializer operation/executor/verifier tables and ADR-043 `NamedVolumeSeed`/`SeedFile`/`seed_named_volumes()` path. Extend their typed input and exact readback rather than adding raw Docker copy calls. |
| Generated artifacts | `raes_stateful_realization.py`, `ComposeStatefulRealizationMixin`, stateful graph/effective-model validators, generated-artifact observation, `ensure_soc_certs()`, and the SSH key builders. Provider-specific cryptographic checks stay with those providers. |
| Config, environment, and secrets | Strict `AptlConfig`/`ScenarioSourceConfig`, `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, placeholder checks, `.gitignore`, hatch/package asset exclusions, and ADR-028/029/034. |
| Errors, logs, and persistence | RAES `Diagnostic`, `render_raes_diagnostics()`, unsuccessful `ApplyResult`/`LabResult`, `get_logger()`, `redact()`, `LocalRunStore`, `RangeSnapshot`, and artifact-satisfaction/runtime-snapshot contracts. No new exception hierarchy or workflow state machine. |

The current codebase has two containment exception types. Pack/bundle reads use
`aptl.utils.pathsafe.PathContainmentError`; incumbent generated writers keep
their existing credential/SOC containment errors until separately migrated. Do
not introduce a third.

## Security And Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| Pack ingress | Treat the pack as untrusted. Apply `PackValidationLimits`, RAES `AssociatedArtifactValidationLimits`, structured bounded diagnostics, exact manifest/set/payload validation, descriptor-anchored no-follow reads, immutable staging, and digest re-verification before use. No network or ambient path fallback. |
| RAES shape and semantic validation | Every content item states type, target, exact source identity, destination, sensitivity, and any exact service-materialization ownership/readback references. Generated outputs, consumers, dependencies, lifecycle, sensitivity, relative output paths, and absolute in-range destinations pass RAES's closed models and semantic joins. |
| Planner/capability gate | Availability is address-scoped from the validated pack; the backend advertises only the pack mechanism, generated kinds, service profile, and observation strength it executes and independently reads back. Missing identity, bytes, provider, output, consumer, or readback is a blocking diagnostic before mutation. |
| Config and selection shape | Keep operator selection in strict `AptlConfig`/catalog resolution. A future acquired-pack selector is an identity/version/digest/trust-policy input, not an arbitrary path, URL, import root, environment-key name, or free-form provider map. `ScenarioSourceConfig.root` remains transitional operational config and never becomes SDL semantics or persisted identity. |
| Operator secret/environment binding | Operator `.env` remains anchored to `project_dir`, parsed through existing typed env/placeholder gates. A bundle-local `.env` never becomes Compose interpolation or control-plane input. A deliberately planted synthetic `.env` is a sensitive pack artifact with provenance/content-safety review and an explicit in-range destination, not an operator secret. |
| Path and destination policy | Artifact IDs are not paths. Content targets/types pass RAES validation; destinations additionally pass APTL's canonical absolute/relative destination checks, containment/symlink defenses, named-volume validation, and generated-output/mount-conflict gates. No source bytes may be satisfied from the engine checkout, CWD, `$PATH`, package imports, operator `.env`, or generated-state directories. |
| Generated-secret handling | Preserve owner-only staging directories, atomic writes, private/public file modes, no-follow checks, read-only least-privilege mounts, key/certificate relationship checks, and package/archive exclusions. Never put private keys, CA keys, passphrases, PEM bodies, or authorized-key contents in DTO details or evidence. |
| OS/process and Docker exposure | Use existing typed argv-list runner methods and bounded timeouts. A non-secret staging path may necessarily appear in local `ssh-keygen`, Docker, or Compose argv/daemon mount metadata; source bytes, private bytes, passphrases, environment values, credential-bearing URLs, and scenario-provided shell never do. Do not add `shell=True`, tar pipelines, or generic host execution. |
| Effective runtime model | Validate exact bind source, destination, access mode, project ownership, and absence of mount conflicts before start; independently inspect the consumer after start. Preserve `supports_local_artifacts=False` for SSH Compose until a separate digest-verifying remote-staging contract exists. |
| Authentication/network surface | This issue adds no endpoint, participant authority, host port, or network grant. Existing `verify_token`, `WebAuthSettings`, BFF Host/CSRF/session gates, loopback defaults, ACLs, internal networks, SSH host-key verification, and participant observation boundaries remain unchanged. |
| Error envelope | Pack/parser/planner failures are stable bounded diagnostics. Provider/backend failures are unsuccessful existing result envelopes. Never echo authored bytes, raw YAML/Pydantic/cryptography/subprocess errors, full commands, absolute roots, environment maps, Docker stderr, or key paths to CLI/API/run records. |
| Logging and persistence | Log non-secret addresses, artifact ids/digests, provider profile, and boolean phase outcomes through `get_logger()` and redaction. Persist pack/set/artifact identities, destination declarations, satisfaction/readback evidence, and sensitivity labels through existing RAES/RunStore surfaces; omit operational roots and generated bytes. |
| Distribution boundary | Keep operator `.env`, generated roots, caches, lab SSH material, and SOC CA material excluded by `.gitignore`, `_asset_manifest`, hatch build hooks, Docker context exclusions, and APTL release archives. The intentionally planted synthetic portal environment file is instead an explicit sensitive pack artifact (it need not use `.env` as its pack filename) whose destination is `.env`; pack provenance/content-safety gates classify it and forbid real credentials. |

## Extensibility Seams

The primary seam is a per-start authorized resolver:

`(pack identity, pack version/set digest, scenario entry point, opaque artifact
id, trust policy, limits) -> validated ScenarioBundle + immutable
ResolvedArtifact bytes/identity`

The next reasonable acquisition variation (an immutable local archive, signed
catalog object, or offline-staged release) changes only that resolver and trusted
availability facts. Content interpretation and deployment do not learn a URI
scheme, catalog, checkout layout, or staging path. There is no fallback from a
failed acquired source to the APTL tree.

Generated artifacts extend independently by a typed
`(generator kind, producer profile)` provider registered in the existing
stateful realization path. Each provider declares its canonical staging policy,
output-set and sensitivity validation, consumer mount behavior, and non-secret
readback. Adding another certificate service varies
`SOC_SERVICE_REGISTRY`; adding another artifact class varies the upstream RAES
kind and this exhaustive provider map, not a scenario-name branch or generic
script hook.

## Whole-Repository Surface In Scope

- Scenario and dependency authority:
  `scenarios/techvault-operational.sdl.yaml`, the future environment-pack
  artifact manifest, `scenarios/catalog.json`, `pyproject.toml`, and
  `uv.lock`.
- Acquisition and planning:
  `src/aptl/core/{config,scenario_catalog,scenario_bundle}.py`,
  `src/aptl/backends/raes.py`,
  `raes_{manifest,artifact_mechanisms,artifact_availability,realization}.py`,
  and RAES parse/compile/plan/conformance.
- Content realization:
  `raes_{content_realization,image_free_content_realization,materializer,`
  `materializer_engine,docker_materializer,observation}.py`,
  `src/aptl/core/content_seed.py`, and
  `src/aptl/core/deployment/{realization,backend,docker_compose}.py` plus
  `_compose_content_realization.py` and the named-volume seed safety/attribution
  helpers.
- Generated artifacts and lifecycle:
  `raes_stateful_realization.py`, generated-artifact observation,
  `src/aptl/core/deployment/_compose_stateful_*`,
  `_stateful_certificates.py`, `src/aptl/core/{lab,ssh,soc_ca,_soc_ca_*}.py`,
  bind-mount preflight, retries, cleanup, and snapshots.
- Security/distribution:
  `src/aptl/utils/{pathsafe,redaction,logging}.py`,
  `src/aptl/core/{env,credentials,runstore,snapshot,assets}.py`,
  `.gitignore`, `.dockerignore`, `_asset_manifest.py`, hatch build hooks,
  archive/release gates, and API auth/error projections.
- Verification:
  content lowering/materializer/seed/readback tests, stateful provider/graph/
  mount/observation tests, SSH and SOC CA crypto/permission tests,
  scenario-bundle differential tests, pack missing/extra/symlink/digest tests,
  TechVault static/live gates, supply chain/asset-leak tests, RAES conformance,
  `pytest`, `pre-commit run --all-files`, and the clean lab restart required by
  `.gc/plan-rules.md` for deployment/config changes.

## Gotchas And Anti-Patterns

- Do not replace `source.name: containers/...` with
  `source.name: assets/...`, `file:...`, or another disguised path. Use an
  opaque artifact id plus exact RAES identity.
- Do not use Git tracking, `.gitignore`, a Docker context, a directory walk, or
  a comment as inventory. The current ignored planted `.env` and local
  `__pycache__` directories demonstrate both failure directions.
- Do not recursively copy a source directory or accept a destination directory
  merely because it exists. Seed only declared bytes and reject undeclared
  collisions in owned sets.
- Do not inline whole source trees or duplicate the associated-artifact
  manifest inside SDL. Component software uses the source-artifact path;
  scenario bytes are referenced once by exact identity.
- Do not model application code, package metadata, capture tooling, bootstrap
  executables, generated flags, SSH keys, certificates, mutable databases, or
  evidence as interchangeable “content.”
- Do not treat a `certificate_bundle` as an SSH-key bundle, use
  `rendered_config` as the fallback for an unknown generator, or use a
  filesystem `provenance` string as provider dispatch.
- Do not give every generated output to every consumer. In particular, never
  mount the SOC CA private key, Kali pivot private key, workstation pivot
  private key, or another service's leaf key into an unrelated node.
- Do not generate pivot keys/SOC certificates from global config flags before
  scenario admission, and do not reparse/replan merely to decide generator or
  bind ownership.
- Do not advertise `service-content-v1`, a pack artifact mechanism, a generated
  kind, or daemon/guest observation strength before exact execution and
  independent readback pass end to end.
- Do not let sensitive content or generated material enter build layers,
  process argv, logs, diagnostics, telemetry, API envelopes, snapshots, run
  records, packages, or archives.
- Do not add a pack-content schema, checksum model, URI parser, source enum,
  exception hierarchy, workflow state machine, raw Docker copy path, or
  scenario-specific provider branch in APTL.

## Non-Goals And Boundaries

This issue does not make APTL the environment-pack format authority, redesign
RAES artifact/generated-content schemas locally, implement a network registry,
entitlements, signatures, or arbitrary URL/path acquisition, or make the SSH
Compose backend transport controller-local artifacts. Required upstream public
APIs/schema additions are prerequisites, not scope silently absorbed into an
APTL approximation.

It does not claim the whole base filesystem as scenario content, replace
component source work from ADR-051, redesign Docker Compose, change participant
actions/evidence/scoring, alter intended synthetic vulnerabilities or
credentials, rotate operator secrets, or migrate the operator control-plane SSH
private key into the scenario. It also does not redesign all Wazuh stateful
artifacts; changes there are limited to keeping provider dispatch, isolation,
and exact-output guarantees consistent when the shared generated-artifact path
is extended.

The implementation boundary is portable content identity, explicit in-range
placement, declared scenario-generated artifacts, fail-closed exactness, and
reuse of the existing admission/realization/observation pipeline on the local
packaged Docker target.
