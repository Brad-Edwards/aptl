# Issue #889 Cortex Initial Service State Preflight

This note fixes the APTL boundary for RAES ADR-088 service-target
materialization. It is architecture guidance, not an implementation plan. RAES
ADR-088 and the installed `initial-service-state` specification own the
portable contract; APTL ADR-046 owns dynamic realization and observation, and
ADR-051 owns the component-versus-scenario-state boundary. No new APTL ADR or
desired-state schema is needed.

## Architecture Decisions

### Keep one portable contract and one native adapter boundary

The authored and compiled authority is RAES
`ServiceSearchIndexSchemaMaterialization` / its compiled binding, with profile
`service-search-index-schema` version `1`. APTL must consume that closed binding
through the existing content-placement lifecycle. It must not mirror its fields,
re-parse the SDL payload, or create a service-materialization plan beside the
RAES provisioning plan.

APTL needs one typed operational carrier through the existing
`PlacementRealization` -> `AptlRealization` -> `DeploymentRealizationSpec` ->
`DeploymentBackend` boundary. The carrier retains the compiled resource
address, exact target service address, profile/version, portable requirements,
readback contract, and RAES canonical digest. Provider-native data is attached
only at the deployment adapter boundary. Carry or wrap the RAES compiled
binding; do not restate those fields in an APTL-owned DTO.

That adapter boundary is a closed, backend-owned binding keyed by:

`(compiled content address, exact target service address, interface profile,
profile version)`

Its value selects the provider adapter, native store identity, internal
connection target, and bounded readiness/operation timeouts. For TechVault it
binds `provision.content.cortex-job-index-schema` and the declared Elasticsearch
service on `thehive-es` to the existing `cortex_6` datastore partition. The SDL,
plan, runtime snapshot, participant projection, logs, and public diagnostics
must not contain `cortex_6`, an Elasticsearch endpoint, request syntax, or
credentials. Do not infer a native partition from a field count, service name,
or whichever datastore entry happens to be present; validate the configured
binding against the target node's declared datastore inventory and fail on a
missing or ambiguous match.

This registry is the extensibility seam. A second search-index materialization
or a second native provider adds a binding and adapter implementation without a
Cortex branch in the interpreter, Compose orchestrator, observer, or live gate.
The portable-semantic-to-provider-type projection belongs to the provider
adapter and must cover every semantic that APTL advertises for profile v1, not
only TechVault's current `exact-token` fields.

### Make native state a provisioning barrier

Service materialization is part of the existing content-placement lifecycle,
not a node, generated artifact, stateful volume seed, post-start repair, or
live-gate action. Its ordering contract is:

`validated model -> target service and dependencies ready -> native reconcile
-> fresh native readback -> remaining consumers start -> full health and
independent observation`

The Compose backend must express that as a generic target-service startup
barrier using its typed runner and existing health machinery. Starting the
whole profile and repairing the index afterward races Cortex. A helper container
that remains in `docker ps -a` also violates bidirectional parity. If a bounded
disposable helper is ever required by another provider, ADR-046 already requires
it to be resource-derived, project-owned, evidence-bound, and absent from the
steady-state graph; it is not permission to restore a declared one-shot VM.

Reconciliation is idempotent and non-destructive:

- create the missing native store with the exact portable projection;
- accept an existing store only after fresh readback proves every declared
  field at equal semantic strength;
- reject missing, ambiguous, weaker, or incompatible mappings and unowned
  collisions; and
- never delete/recreate an index, enable dynamic auto-creation, or adopt a
  collision, even when the existing index is empty.

Reset and destructive data recreation remain separate lifecycle policy. The
current `cortex-index-init.sh` empty-index delete/recreate branch is therefore
not reusable as-is. `cortex-apikey.sh` must not invoke index initialization as a
second repair authority.

### Prove the claim twice, without echoing the plan

Successful reconciliation requires structured native readback from the target
service. The provider projects the response back to portable field semantics,
recomputes the digest with RAES's canonical digest utility, and compares it with
the admitted binding. Raw provider responses and undeclared extra fields are not
portable evidence. Profile v1 permits extra native fields, but every declared
field must be present with at least the declared semantic strength.

`observe_realization()` must perform a new native read after backend success.
Only that independent observation may add the exact compiled
`service_materialization` binding to the content-placement concern map. Reusing
the apply result, manifest, generated Compose, or planned payload is a
planned-state echo and must fail SEM-218. Reuse `ObservedResource` and the
existing runtime-snapshot path; do not add a service-state snapshot DTO.

Safe operation evidence identifies the compiled address, profile/version,
canonical projected digest, observation strength, freshness/operation binding,
and outcome. It excludes the native identifier, endpoint, command, request or
response body, credentials, and raw stderr. The same live-gate realization
check consumes this proof; do not create a Cortex-only tenth check or a second
report schema.

The backend manifest may advertise
`service-search-index-schema-v1`, exact support for
`service-search-index-schema-materialization`, and the content-placement
realization envelope only when the operational adapter, independent observer,
and conformance fixtures all exist. `realization-envelope-v1` is a whole-backend
claim: add its closed, secret-free realizer-configuration digest and all required
concern dispositions truthfully rather than constructing a content-only partial
envelope.

### Remove mechanism-based liveness exceptions

The repository audit found no authored TechVault node with container
`autoremove: true`; the updated environment pack contains no
`cortex-index-init` node. The remaining systemd `Type=oneshot` units execute
inside running VM containers and do not use container liveness exceptions.
The retired static `cortex-index-init` Compose service is migration input only
and is removed by the implementation.

Accordingly, remove the restart-policy/exit-zero recognition from
`container_settled()`, `container_realized()`, and live-gate readiness. An exited
declared VM is not realized or ready. Do not leave `_operational_config()` able
to translate RAES `autoremove` into `restart: "no"` while every observation gate
rejects the result: remove that dormant support or reject it during admission.
Any future genuine run-to-completion resource requires an authored portable
lifecycle contract and fresh result evidence; Docker restart metadata is not
that contract.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| SDL, semantics, and digest | RAES `Content.service_materialization`, `ServiceSearchIndexSchemaMaterialization`, semantic validator, compiler, `ServiceSearchIndexSchemaMaterializationBinding`, `canonical_json_digest`, and the initial-service-state specification. Do not add local enums or validation. |
| Planner admission | RAES `service_materialization_diagnostics()`, provisioner profile capability, exact realization-support kind, content-placement concern path, and direct-submission admission. Both planner and direct paths must fail before side effects. |
| Interpretation | `interpret_provisioning_plan()`, placement dispatch, `PlacementRealization`, and `AptlRealization`. Dispatch service materialization before the ordinary dataset resolver; do not weaken that resolver's non-empty-item contract. |
| Deployment | `DeploymentRealizationSpec`, `DeploymentBackend`, `ComposeRealizationMixin`, generated Compose validation, target health waiting, local/SSH Compose runners, timeouts, and project scoping. Add a typed operation rather than raw Docker or Compose argv passthrough. |
| Datastore identity | The target RAES `RuntimeDatastoreService` partition/mapping declaration plus one closed APTL provider binding. The runtime datastore remains observed inventory; it is not a duplicate authored schema. |
| Observation and persistence | `ObservedResource`, `observe_realization()`, `snapshot_after_apply()`, RAES concern payload registry, operation evidence, `RangeSnapshot`, and `LocalRunStore`. Persist canonical, redacted proof metadata only. |
| Manifest and conformance | `create_aptl_manifest()`, `ProvisionerCapabilities`, `RealizationSupportDeclaration`, the RAES realization envelope, `create_aptl_runtime_target()`, in-process target conformance, published CLI conformance, and static/live gates. |
| Errors, retry, and logging | RAES `Diagnostic`, `render_raes_diagnostics()`, unsuccessful `ApplyResult`/`LabResult`, `StartupDiagnostic`, `get_logger()`, and `redact()`. Use stable address-scoped codes; do not add an exception hierarchy. |
| Legacy Cortex mechanics | `scripts/cortex-index-init.sh`, `scripts/cortex-apikey.sh`, the static Compose service/dependency, and `_component_profiles.py` are migration inputs to retire or consolidate, never parallel authorities. |

## Security And Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| RAES shape and semantic validation | The closed profile/version, operation, conflict policy, portable field semantics, target service, readback assertion/evidence/boundary refs, and ownership joins pass RAES Pydantic and semantic validation. APTL receives only the compiled binding. |
| Capability and plan admission | The provisioner profile, exact support kind, concern path, observation strength, and realization envelope all match the implemented path. Unsupported semantics, targets, versions, or missing bindings fail before Docker mutation. |
| APTL typed-shape validation | The binding survives the existing realization DTOs with its address and digest intact. Generated Compose ownership/parity validators see no scenario node or persistent helper for the operation. |
| Config and environment | No authored or operator-facing free-form config is needed for the TechVault binding. If later provider credentials are configurable, they pass strict `AptlConfig`, dotenv hydration, `EnvVars`, placeholder validation, and existing sensitivity rules; SDL fields never become environment-variable names or native commands. |
| Authentication and secrets | Current `thehive-es` is unauthenticated only on the internal `aptl-security` network, so this change creates no public auth surface. A future authenticated adapter resolves credentials at the backend boundary and sends them through a typed backend stdin/0600-file channel following the existing `curl_safe` pattern; values never enter the plan, manifest, snapshot, argv, URL, or logs. |
| Network and OS exposure | Reuse the declared target network and local/SSH `DeploymentBackend` so the operation reaches the same Docker daemon as the lab. A local host `curl` cannot bypass that boundary. Add no host port. Commands are fixed argv with bounded input/output and timeout; no `shell=True`, scenario-provided query, or request body in process arguments. |
| Native response validation | Parse bounded JSON structurally, reject malformed/oversized/ambiguous output, project only known portable semantics, and compute the canonical digest. Grep or substring checks against Elasticsearch JSON are not evidence. |
| Error envelope | Provider and parser failures become redacted, stable RAES/APTL diagnostics. Do not expose endpoints, native ids, mappings, commands, request/response bodies, Docker stderr, or Pydantic `input`/`ctx`. Incompatible state and readback mismatch are non-retryable; transient target readiness retries are bounded inside the adapter so the outer clean boot does not require its forced retry. |
| Logging and evidence persistence | Log address, profile/version, digest, phase, duration, and outcome through `get_logger()`/`redact()`. Persist only the same safe proof plus freshness and observation strength through existing operation/snapshot/run-store contracts. |
| Participant and public surfaces | Initial datastore state is infrastructure evidence. It adds no participant action, observation, node, credential, endpoint, or workbench link and does not widen the endpoint registry or host firewall surface. |

## Whole-Repository Surface In Scope

- The pinned `raes` and `raes-env-packs` contracts, TechVault pack SDL and lock,
  RAES parser/compiler/planner/direct admission, runtime concern registry, and
  conformance corpus.
- APTL RAES manifest, diagnostics, placement interpretation and typed
  realization models, observation helpers, runtime snapshot, apply status, and
  retry classification.
- Deployment realization DTOs/protocol, local and SSH Compose backends,
  generated-model validation, dependency/health ordering, typed container or
  service operations, timeout policy, and teardown/project ownership.
- Static `docker-compose.yml`, `scripts/cortex-index-init.sh`,
  `scripts/cortex-apikey.sh`, component-profile accounting, the target
  Elasticsearch datastore inventory, and Cortex dependency wiring.
- Static and live TechVault gates, RAES conformance tests, realization and
  observation tests, Compose health/readiness tests, security/secret-leakage
  tests, and clean `aptl lab stop -v && aptl lab start` validation.
- `.ground-control.yaml`, `.gc/plan-rules.md`, `.pre-commit-config.yaml`, CI,
  `pytest`, and `pre-commit run --all-files` remain the completion workflow.

## Gotchas And Anti-Patterns

- Do not model the operation as a VM, Compose service, node lifecycle exception,
  generated artifact, volume seed, healthcheck, live-gate repair, or Cortex
  startup script.
- Do not copy RAES profile models, semantic enums, digest rules, readback refs,
  or validation into APTL. Do not add a second plan, repository, controller,
  workflow, snapshot shape, exception hierarchy, or report.
- Do not advertise the profile from a manifest declaration, fake adapter,
  static-gate echo, or planned payload. Capability follows operational native
  mutation plus independent readback and conformance.
- Do not key provider behavior on `cortex`, `thehive-es`, a scenario/catalog
  name, field count, or the first index partition. Dispatch by the exact typed
  binding and fail closed.
- Do not support only `exact-token` while claiming the whole v1 profile.
- Do not make the legacy shell script and a Python/native adapter two writers.
  Keep one provider implementation and one readback projection.
- Do not delete/recreate incompatible state, silently accept weaker mappings,
  enable Elasticsearch auto-create, or treat index existence/count as schema
  proof.
- Do not run materialization after Cortex, cache apply readback as observation,
  leave a stopped helper in project inventory, or add a Cortex-specific live
  check.
- Do not send credentials or JSON bodies in argv, interpolate SDL into shell or
  query syntax, expose Elasticsearch on the host, or persist raw native output.
- Do not classify deterministic contract conflicts as generic retryable backend
  startup failures.

## Non-Goals And Boundaries

- Changing RAES ADR-088, its closed profile, canonical digest, or environment
  pack schema is out of scope; APTL consumes the pinned released contracts.
- Inserting Cortex jobs or other documents is out of scope. This requirement
  establishes the field schema only; schema-only content has no dummy item.
- General database migration, arbitrary query execution, an Elasticsearch SDK
  abstraction, multi-provider discovery, and operator-authored native mappings
  are out of scope.
- Redesigning the `thehive-es` service, enabling Elasticsearch security, adding
  host exposure, changing Cortex API-key lifecycle, or redefining datastore
  inventory is out of scope except for removing the duplicate index repair.
- Redesigning systemd one-shot units inside otherwise running nodes is out of
  scope; they do not satisfy or consume container liveness exceptions.
- Changing live-gate report count/schema, participant visibility, destructive
  reset policy, or the generic content-seeder lifecycle is out of scope.
