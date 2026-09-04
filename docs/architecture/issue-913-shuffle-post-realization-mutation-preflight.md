# Issue #913 Shuffle Post-Realization Mutation Preflight

This note fixes the architecture boundary for retiring the TechVault Shuffle
backend replacement. It is guidance, not an implementation plan. No new ADR is
needed: ADR-046 and ADR-051 already require complete admitted desired state,
readback, and fail-closed realization; ADR-029 owns secret handling; ADR-034 owns
the SOC trust boundary; ADR-053 prevents the deployment-serving interaction
plugin from becoming a configuration side channel. Issue #913 applies those
accepted decisions to Shuffle.

## Findings And Released Contract

The pinned inputs are `raes==3.3.0` and `raes-env-packs==4.0.2`. That env-pack
release resolves OpenRAE/env-packs#281 and is authoritative for the TechVault
Shuffle contract. In addition to the existing exact image artifacts, topology,
services, dependencies, retained volumes, Orborus authority, frontend
certificate bundle, and OpenSearch inventory, it declares the complete
`shuffle-backend` runtime environment, its application-to-datastore binding,
and authenticated datastore-operation readiness.

The selected internal datastore endpoint is
`https://shuffle-opensearch:9200`. Its transport mode is TLS while client and
node certificate verification are explicitly disabled; the backend runtime
therefore declares `SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true`. This is an authored
posture for the disposable internal lab datastore, not a value chosen by APTL.
Endpoint identity and verification posture remain separate observations: APTL
must prove that the declared endpoint and disabled-verification posture were
realized, but must not report certificate identity as verified. The independently
exposed host-facing Shuffle frontend remains under ADR-034's strict lab-CA
verification boundary.

Before 4.0.2, `scripts/envpack-soar-fixups.sh` repaired the missing runtime only
after planning and realization by deleting and recreating `shuffle-backend`.
That replacement invalidated realization evidence and added undeclared mounts
and environment. With 4.0.2 the admitted plan contains those concerns, so the
replacement branch is removed. The existing bounded authenticated Shuffle API
wait remains as the seed/prime readiness boundary; it observes readiness but
does not mutate infrastructure. General bidirectional runtime closure and
service-native probe infrastructure remain tracked by #915 and #916 rather than
being reimplemented as Shuffle-specific machinery here.

## Decisions And Ownership Boundaries

1. **The released pack owns authored Shuffle intent.** Every required backend
   and datastore concern is either concrete authored state or an explicitly
   open/constrained concern under RAES semantics. Omission is not openness:
   `classify_authoring_specificity()` requires an admitted open path, and its
   own contract says that authoring openness is not backend-realization
   permission.
2. **The RAES plan owns all effective pre-mutation requirements.** APTL stages
   the immutable installed pack through `scenario_bundle`, validates its exact
   content inventory, parses it into RAES models, and lets `RuntimeManager.plan`
   resolve the backend envelope before `DeploymentBackend.realize` is called.
   Any unresolved, unsupported, or invalid concern blocks before Docker,
   generated-artifact, network, volume, or content mutation.
3. **Backend selections stay distinct from authored requirements.** RAES's
   realization envelope admits the backend posture before apply; constrained
   paths use its domains and closure, while an open path remains explicitly
   unbound. The provisioning plan carries the open/constrained requirement, and
   runtime observation carries the chosen value. The SEM-218 gate records the
   choice separately as `BACKEND_REALIZED` in
   `RuntimeSnapshot.realization_provenance`; it is not rewritten into the pack
   or mislabeled `AUTHOR_DECLARED`. Provenance carries paths and classes, never
   secret values.
4. **Generated Compose remains a projection, not a policy source.** The
   operational renderer emits the plan's typed `RuntimeConfiguration`. It must
   not grow Shuffle defaults, a legacy-Compose merge, a product-name switch, or
   a late environment overlay. The existing universal ulimit fallback remains
   the sole documented temporary backend default until its upstream affordance
   exists; any new selected value requires separate envelope/provenance
   disclosure.
5. **Readiness precedes content seeding.** Container `running` alone is
   insufficient for a backend whose correctness depends on OpenSearch. The
   released contract declares authenticated datastore-operation readiness, and
   the existing bounded authenticated API wait must succeed before Shuffle
   workflow content is seeded. Seed scripts do not repair runtime.
6. **Endpoint identity and transport verification are separate facts.** The
   endpoint binding and selected verification posture are independently
   admitted and observed. For the released internal datastore contract,
   verification is deliberately disabled, so a successful connection proves
   reachability and authentication—not certificate identity. No evidence may
   label that connection as identity-verified.
7. **Persistence follows the declared stateful graph.** The existing retained
   backend and OpenSearch volumes and their exact mount destinations remain the
   authority. Normal stop/start preserves them; only the existing explicit
   `stop -v` or `start --clean` surface resets them. No readiness probe may
   delete application data, recreate a container, or silently initialize a new
   volume under a hand-composed name.
8. **Failure does not trigger replacement or implicit rollback.** A trust,
   authentication, datastore, readiness, or observation mismatch returns an
   unsuccessful realization. Issue #905's lifecycle contract then governs the
   project-scoped residual state and explicit recovery. There is no automatic
   container swap, volume deletion, retry-by-recreation, or fallback to the
   static `docker-compose.yml`.
9. **The workaround is narrowed, not repurposed.** The Shuffle replacement call
   and implementation in `envpack-soar-fixups.sh` must be removed or made
   structurally unreachable. The script's independently tracked MISP and
   endpoint-publication work is not evidence that the Shuffle runtime repair
   should remain, and issue #913 does not silently absorb those defects.

## Required Concern Classification

The #281 release is authoritative for exact field names and classifications.
The following concern classes must nevertheless be visible in its admitted
contract; this is a completeness check, not permission for APTL to synthesize
them:

| Concern | Required ownership and observation |
| --- | --- |
| Backend source and topology | Exact pinned image, backend service/listener, dependency on the datastore, network attachment, and stable service identity come from the pack and are observed through the existing image/network/service concerns. |
| Backend operational configuration | Datastore endpoint, application timeout/defaults, bootstrap identity, and any other required `SHUFFLE_*` inputs are authored or explicitly open. Missing and substituted values fail runtime-environment observation. Excess APTL-injected values fail the closed effective-configuration comparison. |
| Credentials | Fixture credentials are explicitly `secret_fixture`; deployment/operator credentials are `operator_secret` and supplied through `.env`; public identifiers remain non-secret. A credential-looking name is not itself a classification. |
| Backend-to-datastore trust | TLS transport, selected endpoint identity, and the explicitly disabled client/node verification posture are separate declared facts. No internal CA/trust anchor is selected, and readiness evidence must not claim certificate verification. |
| Datastore runtime | OpenSearch engine/version, listeners, single-node/cluster posture, resource settings, security settings, authorization reference, partitions/mappings, and transport security use RAES's typed datastore/runtime surfaces. Do not duplicate them as an APTL Shuffle DTO. |
| Persistence | Both retained volumes, access modes, consumers, destinations, and ordering remain pack-authored stateful resources and are read back through the stateful graph. |
| Orchestration privilege | The pinned pack assigns host-root-equivalent Docker authority to Orborus. Do not copy it onto `shuffle-backend` merely because the legacy Compose file or workaround did so. If the #281 release deliberately authors a separate backend authority, it must pass the same admitted concern and excess/readback gates; a vendor default or image convention is not authority. |
| User-facing Shuffle TLS | The frontend's lab-CA certificate and loopback publication remain the ADR-034 SOC-consumer surface. They are distinct from backend-to-OpenSearch identity and verification. |
| Readiness and datastore operations | The backend must authenticate and perform a bounded disposable datastore operation through its configured connection before success. This is observed operational evidence, not an authored claim or a seed-script warning. |

For closed effective configuration, compare the container's realized
environment with the admitted runtime after subtracting `Config.Env` read from
the exact observed image and only the fixed APTL substrate additions already
owned by the runtime excess gate. The existing image digest/config-ID readback
is the identity seam; if image-config readback is required, extend the typed
`DeploymentBackend` observation surface instead of invoking raw Docker. There
is no APTL environment allowlist to hard-code. Do not reject ordinary
image-owned variables such as `PATH`, and do not bless arbitrary variables
merely because the image happens to accept them. The closure scope is the
#281-governed Shuffle configuration surface; it must not be reconstructed from
a hard-coded `SHUFFLE_` prefix or from the legacy Compose file.

Mount closure needs the same care. Runtime-mount observation currently closes
bind and tmpfs mounts, while stateful observation proves declared named volumes
and effective Compose validation accepts their presence and identity. Neither
currently rejects an additional named-volume mount on the backend. Extend the
typed runtime/stateful excess observation for that delta; do not mistake the
existing declared-volume readback for bidirectional closure.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Pack acquisition and validation | `src/aptl/core/scenario_bundle.py`, `raes_env_packs.validation.validate_pack`, pack manifests/digests, `aptl.validation.techvault_gate.validate_scenario`, and `tests.helpers.techvault_scenario_bundle` remain the installed-pack path and static gate. Never edit the staged copy or add a second pack schema. |
| Planning and admission | `AptlProvisioner`, `RuntimeManager.plan`, `interpret_provisioning_plan`, RAES blocking diagnostics, and `_run_execution_plan` must see the complete concern set before `DeploymentBackend.realize`. Do not perform first-time selection in Compose or shell. |
| Open/constrained selection | `build_aptl_realization_envelope()`, RAES `BackendRealizationEnvelopeModel`, canonical envelope/configuration digests, and RAES explicitness classes/provenance own admission and disclosure. Constrained domains and any deterministic witness policy stay in that contract; open values remain unbound until backend realization and are then reported through observed state plus `BACKEND_REALIZED` provenance. Do not add an APTL `selected_values` map or put realized secrets in the envelope. |
| Runtime DTO and rendering | `raes.runtime_configuration.RuntimeConfiguration`, `DeploymentNodeRealization.runtime`, `_compose_node_generation._operational_config`, runtime mount lowering, and stateful overrides are canonical. They are strict Pydantic/RAES shapes with no extra-field escape hatch. |
| Runtime closure/readback | `raes_runtime_observation`, `_runtime_concern_excess`, `_raes_stateful_observation`, `raes_observation`, and the SEM-218 non-approximation gate own missing/substituted/excess rejection. Extend their typed image-config and named-volume observations where current coverage stops; do not add a post-start `docker inspect \| grep` gate or claim that declared-only observation closes the delta. |
| Certificates and trust | The pack-authored `certificate_bundle`, `SOC_CERT_PROFILE`, `derive_soc_service_certs`, `ensure_soc_certs`, `_stateful_certificates`, selected-output mounts, and `_raes_stateful_observation` own generated material, SAN/chain/key validation, containment, permissions, and non-secret evidence where verification is selected. Release 4.0.2 does not select an internal `shuffle-opensearch` trust anchor. |
| Stateful resources | `raes_stateful_realization`, `_compose_stateful_model`, `_compose_stateful_graph`, `_compose_stateful_realization`, effective Compose validation, and project-scoped volume cleanup own persistence. Reuse the declared `shuffle_data` and `shuffle_opensearch_data` resources. |
| Backend operations | `DeploymentBackend` plus local/SSH Compose implementations own inspect, exec, lifecycle, and remote-daemon behavior. Native probes use `container_exec_with_input` as `_service_index_materialization` does, keeping scripts and payloads off host argv. No new raw-Docker shell path is admissible. |
| Polling and readiness | `_compose_post_start`, `wait_for_realized_health`, `ReadinessPolling`, `core.services.wait_for_service`, and the bounded Shuffle API wait own deadlines and fail-closed sequencing. Issue #913 removes repair from that wait path; generic service-native realization probes remain #916 scope. |
| Environment and credentials | RAES `RuntimeEnvironmentVariable`, `load_dotenv`, `find_placeholder_env_values`, Compose's explicit control-plane `--env-file`, and runtime-environment observation own the binding. Derive required `operator_secret` names from the admitted runtime and reject absent/placeholder values before `DeploymentBackend.realize`; Compose interpolation is emission, not validation. `EnvVars` remains the Wazuh-specific typed view and must not become a Shuffle schema. |
| HTTP and authentication | `aptl.utils.curl_safe`, `basic_auth_header`, 0600 temporary header/body files, and environment-backed container probes own HTTP secret transport. Tokens/passwords must not appear in host argv, process listings, raw command logs, or failure text. Read protected values inside the admitted container environment; do not put them in a `container_exec_with_input` payload, whose current contract is non-secret input. |
| Result and errors | `LabResult`, RAES `ApplyResult`, `diagnostic()`, `render_raes_diagnostics`, `BackendTimeoutError`, and `_runtime_concern_disclosure` are the canonical envelopes. Return bounded reason codes/classes and redacted summaries; do not create a Shuffle exception hierarchy or expose native bodies. |
| Logging and evidence | `get_logger`, `redact`, runtime observation disclosures, certificate evidence, service-materialization evidence, and `RuntimeSnapshot.realization_provenance` are canonical. Record endpoint identity, verification outcome, datastore/readiness outcome, elapsed time, and provenance without secrets or raw responses. |
| Consumers | `collect_shuffle_executions`, `mcp/mcp-soar/docker-lab-config.json`, the live gate, and range-integration tests retain strict lab-CA verification for the host-facing frontend. Internal datastore verification must not weaken that independent consumer boundary. |
| Lifecycle and workflow | Issue #905's shared lifecycle owner, explicit persistence reset, and residual-state rejection remain binding. `seed-prime.sh` and `seed-shuffle.sh` seed content after realization; they may not mutate infrastructure or convert a failed readiness result into a warning. Repository verification remains `pytest` and `pre-commit run --all-files`; changes to Compose, Dockerfiles, or `config/` require the clean-machine lab cycle from `.gc/plan-rules.md`. |

## Security And Host-Layer Guardrails

- **SDL and pack validation:** rely on RAES's closed Pydantic shapes, semantic
  cross-reference checks, explicitness classification, env-pack manifest/digest
  verification, and the backend capability/envelope validators. Unknown fields,
  an unresolvable open concern, an unsupported generated artifact, or a missing
  binding blocks planning.
- **Environment binding:** non-secret values may be rendered literally only
  when present in the admitted plan. `operator_secret` values use the existing
  `${NAME}` Compose interpolation and derive their required names from the
  admitted RAES runtime. Validate the control-plane `.env` with the existing
  dotenv and placeholder helpers before the first backend side effect;
  `secret_fixture` values are intentional scenario content and are commitment
  observed. `EnvVars` does not currently model arbitrary pack secrets, so do not
  add Shuffle fields to it or mistake successful Compose interpolation for
  admission. Never collapse the two classes or infer sensitivity from a name.
- **Secret at rest:** private keys and temporary request material keep the
  existing owner-only directory/file rules, containment checks, no-symlink
  policy, selected-output mounts, and producer-private handling. Generated
  Compose, snapshots, provenance, diagnostics, and logs must not contain raw
  operator secrets.
- **OS/process exposure:** use list-form backend commands and stdin-fed
  container scripts. Read credentials from the admitted container environment
  inside the probe or use `curl_safe`'s 0600 header files. Never use `curl -u`,
  `docker exec ... -H "Bearer ..."`, shell interpolation, or an environment dump
  that puts credentials in host argv/logs.
- **Trust posture:** release 4.0.2 explicitly selects TLS with client/node
  verification disabled for the internal OpenSearch connection. Observation
  must preserve that distinction and must not turn a successful insecure
  connection into a certificate-verification claim. A substituted endpoint,
  transport mode, or verification flag fails the declared-runtime comparison.
  This does not weaken strict lab-CA verification for the host-facing frontend.
- **Privilege:** backend OpenSearch access alone does not imply host Docker
  control. A Docker socket on `shuffle-backend`, privileged mode, capability,
  bind mount, host publication, or network listener is unexpected unless the
  released contract explicitly requires it and APTL admits and reads it back.
  Orborus's separately declared host-root-equivalent authority is not
  transferable. Conversely, authoring that Orborus authority without a compiled
  realization concern is not proof that APTL enforced it.
- **Probe safety:** use a collision-resistant, issue-owned temporary datastore
  object, bounded request sizes and deadlines, exact ownership marker where the
  native API supports it, read-after-write proof, and cleanup limited to that
  object. Never probe with production indices named in the pack, delete foreign
  state, or accept a mutation response as readback proof.
- **Error envelopes:** distinguish transport unavailable, identity mismatch,
  trust failure, authentication rejection, datastore operation failure,
  unexpected runtime state, and timeout with stable non-secret classifications.
  Do not include URLs containing credentials, authorization headers, full
  environment values, native response bodies, PEM/key paths, Docker stderr, or
  tracebacks in `LabResult`, CLI/API output, logs, or evidence.

## Extensibility Seam And Whole-Repository Scope

Issue #913 consumes the portable node/service/datastore relationships already
released by env-packs and keeps the current bounded Shuffle API readiness wait.
It does not add a second provider, product-keyed default registry, or
Shuffle-specific realization DTO. A future typed service-native realization
probe belongs behind `DeploymentBackend` and is tracked by #916 so local and
SSH-backed Docker remain behaviorally identical. Native semantics must not be
embedded in a universal HTTP-ready boolean or added to Wazuh-specific helpers.

Open/constrained admission is independently parameterized by governed SDL path
in the realization envelope. Constrained paths may use its domains and witness
policy; open paths deliberately carry no domain. The envelope and
`RuntimeSnapshot.realization_provenance`, paired with fresh observed state, are
the seam for future portable backend choices; a product-keyed defaults
dictionary is not.

The implementation must audit these repository and runtime surfaces together:

- `pyproject.toml`, all generated requirement lock files, the installed/staged
  TechVault pack, pack validation, static gate, scenario resolution, RAES
  planning, backend manifest/envelope, plan interpretation, and realization
  observation/provenance;
- runtime environment/container/network/mount/listener lowering, generated
  Compose, effective-model validation, image and runtime readback, and
  missing/substituted/excess enforcement;
- certificate-bundle generation/validation/observation, SOC CA outputs and
  consumers, `.env`/`EnvVars`, safe HTTP, redaction, and bounded diagnostics;
- stateful graph/overrides, project volumes, normal stop/start, explicit `-v`
  reset, residual-state handling, local and SSH deployment backends;
- Compose health, authenticated/service-native readiness, native datastore
  operations, snapshot evidence, and the live realization gate;
- `scripts/envpack-soar-fixups.sh`, `seed-prime.sh`, `seed-shuffle.sh`,
  `provision-range.sh`, the systemd workflow note, collectors, the SOAR MCP
  config, and range-integration tests;
- the Docker daemon's image/container configuration, process argv and stdin,
  container environment, mounts, capabilities, listeners, networks, certificates,
  persistent volumes, and host-loopback publications.

## Proof Obligations

Regression evidence must demonstrate the contract rather than the absence of a
particular shell call:

- a clean TechVault realization reaches authenticated Shuffle API readiness and
  a native OpenSearch write/read/delete proof while the original realized
  `shuffle-backend` container identity remains unchanged;
- the admitted plan contains every #281 concern, and the runtime snapshot shows
  author/processor/backend provenance correctly without secret values;
- endpoint configuration and the disabled-verification posture are observed
  separately; substituted endpoint or verification values fail closed, and no
  certificate-identity verification is claimed for the internal connection;
- omitted, altered, or injected governed Shuffle configuration, any undeclared
  backend Docker socket/named-volume/bind/tmpfs mount, capability, listener, or
  host port, and unapproved container replacement are rejected;
- normal stop/start preserves a seeded workflow and datastore state, while the
  existing explicit volume reset removes it and permits a new clean realization;
- an authentication error, unavailable datastore, malformed native response,
  operation collision, or timeout returns a bounded redacted failure and never
  reports readiness;
- the host-facing frontend collector and SOAR MCP path continue to validate the
  lab CA, and a trust failure is not hidden by the endpoint proxy or an insecure
  seed request;
- focused static/runtime/stateful/readiness tests and the TechVault live gate
  assert that the Shuffle replacement branch is absent or unreachable and that
  no unexpected container or configuration appears.

## Non-Goals And Anti-Patterns

Issue #913 does not repair the independently tracked MISP mutation, redesign the
endpoint-publication proxy, solve general post-admission mutation enforcement
from #915/#916, replace all shell seeders, redesign Shuffle workflows, change
the Wazuh trust exception, make the internal backend a public host service, add
transactional rollback, or revise the explicit lifecycle reset contract. It
does not migrate all datastore models into the ADR-088 search-index-schema
profile or claim that authored datastore inventory is itself operational proof.

Avoid these anti-patterns:

- copying `docker-compose.yml` or the workaround's literals into APTL code, a
  new config field, a generated override, or the released pack staging area;
- adding pack-specific secret fields to `AptlConfig` or `EnvVars`, or relying on
  Compose's empty/unset-variable behavior as the operator-secret validator;
- treating a missing field as open, selecting an open value after planning, or
  recording a backend choice as author-declared;
- using `pack_interaction` to inject environment, credentials, ports, mounts,
  certificates, readiness, or other deployment state;
- adding a Shuffle DTO, validator, exception tree, Docker client, polling loop,
  certificate registry, persistence path, or logging convention beside the
  canonical incumbents;
- proving readiness with container state, image health, TCP connect, certificate
  presence, a seed-script response, a write acknowledgement without readback, or
  a warning-only loop;
- conflating frontend consumer TLS with backend-to-OpenSearch trust, endpoint
  selection with certificate verification, credentials with authorization, or
  persistent volume presence with datastore correctness;
- hard-coding the closed configuration set from a name prefix, rejecting
  image-owned baseline environment as excess, or allowing image defaults to
  silently fill a scenario-governed requirement;
- putting tokens/passwords in argv, logs, snapshots, provenance, generated
  Compose, error messages, or test failure output;
- granting the backend Orborus's Docker socket without separately authored and
  admitted authority, publishing OpenSearch to the host for convenience,
  disabling verification to make readiness pass, deleting foreign indices
  during a probe, or erasing retained volumes on failure;
- changing the static legacy Compose file as a substitute for fixing and
  consuming the released env-pack contract.
