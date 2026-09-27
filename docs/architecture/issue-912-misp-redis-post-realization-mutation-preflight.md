# Issue #912 MISP/Redis Post-Realization Mutation Preflight

This note fixes the boundary for retiring the temporary MISP/Redis repair. It
is guidance, not an implementation plan. The authoritative desired state is a
released TechVault pack that passes the normal pack validation and admission
path; APTL must not reconstruct that state from its legacy Compose file or the
workaround.

## Release Gate And Decision

**Resolved.** OpenRAE/env-packs#280 closed on 2026-09-16 and its fix shipped in
`raes-env-packs` **6.1.0**, which APTL now pins. That release authors the cache
authorization (`misp-redis-authorization`, value-free `redacted` credential),
MISP's database and cache `upstream_bindings`, the `misp-db` application role
and grant, the `misp-canonical-url` setting, and the
`misp-authenticated-api-readiness` evidence requirement behind a
`misp-authenticated-api-operation` listener probe. The paragraph below records
the state of the pinned 6.0.1 release at preflight time and is kept for the
classification it establishes, not as a current blocker.

Because a pack is one immutable artifact, adopting 6.1.0 also adopts the Wazuh
endpoint-agent contract released alongside #280 (per-host enrollment identity,
retained `/var/ossec/etc` state, a `wazuh-agents-ready` precondition and a
`file_artifact` evidence channel). That is consumed here rather than deferred.

The installed `raes-env-packs==6.0.1` is not sufficient evidence to retire the
workaround. Its realized MISP node has the expected MISP environment shape,
including `ADMIN_KEY` as `operator_secret`, but the rendered node has no
certificate delivery or retained-volume mount. `misp-redis` currently has no
declared command/environment authentication shape. Those are exactly the
classes repaired after realization today. Do not infer the next release's
field names, values, classifications, certificate destinations, or persistence
policy from `docker-compose.yml` or `envpack-soar-fixups.sh`; compare the
released #280 pack with its classification and compilation output.

Once that release is admitted, the decision is:

- Every MISP, MariaDB, and Redis source/topology/dependency, command,
  environment/credential class, generated certificate/config output and
  destination, persistence policy/consumer, listener/publication, resource
  policy, readiness dependency, and MISP-to-Suricata integration is authored
  or intentionally open before `DeploymentBackend.realize`.
- Open values are selected only by the backend through the realization envelope
  and are disclosed as observed `BACKEND_REALIZED` provenance. Missing is not
  open, and an APTL product-keyed default is not a backend choice.
- `scripts/envpack-soar-fixups.sh` contains no reachable MISP/Redis mutation
  branch. It must neither remove/recreate a container nor reset a database or
  volume. `seed-prime.sh` remains content seeding only; it cannot repair
  infrastructure or downgrade a failed readiness result to a warning.

## Required Contract Closure

The release must make these concerns visible through RAES's typed runtime and
stateful contract; this table is a completeness check, not a second schema.

| Concern | Required ownership and proof |
| --- | --- |
| MISP/Redis/MariaDB configuration | Runtime environment, command, dependencies, listeners, resource limits, and operational policy are pack-authored or explicitly open. The existing runtime-environment/command/readback gate rejects missing or substituted governed values. |
| Credentials | Scenario fixture credentials remain `secret_fixture`; deployable API/admin/Redis credentials are classified exactly as #280 specifies, with operator secrets bound from `.env` only after pre-side-effect validation. Never classify by a credential-looking name. |
| TLS and generated artifacts | The pack's `certificate_bundle`, selected outputs, exact MISP image destination, permissions, SAN/chain/key validation, and trust posture are authoritative. A mounted certificate is not evidence that MISP activated it; authenticated MISP readiness must prove the selected endpoint works. |
| Persistence/reset | `misp_config`, `misp_data`, and `misp_db_data` (or their released successors) use the typed stateful graph. Normal stop/start retains declared state; only the existing explicit volume-reset lifecycle removes it. Redis's persistence posture is explicit, not guessed from its image. |
| Runtime closure | Daemon/guest observation rejects omitted, changed, and injected governed environment, command, port/listener, capability, bind/tmpfs mount, local-control interface, and named-volume state. Subtract only the documented image `Config.Env` and fixed substrate baseline; do not create an APTL allowlist or use an environment-name prefix. |
| Readiness | Compose health is only a prerequisite. MISP readiness is authenticated service-native API proof using the admitted credential and selected TLS posture; Redis readiness proves the admitted authentication/command behavior; database readiness proves the admitted database path. A successful seed, TCP connect, login page, or unauthenticated `PING` is insufficient. |

Named-volume excess is the current closure gap: `_runtime_concern_excess` closes
bind/tmpfs mounts and `_raes_stateful_observation` proves declared named-volume
mounts, but declared-only observation is not bidirectional closure. Extend the
typed runtime/stateful observation surface if the released concern requires it;
do not add `docker inspect | grep` or a MISP-specific post-start checker.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and guardrail |
| --- | --- |
| Pack source and validation | `src/aptl/core/scenario_bundle.py`, `raes_env_packs.validation.validate_pack`, content manifest/digest validation, `aptl.validation.techvault_gate.validate_scenario`, and `tests.helpers.techvault_scenario_bundle`. Never edit the staged pack or add an APTL pack schema. |
| Admission and open values | `AptlProvisioner`, `RuntimeManager.plan`, `interpret_provisioning_plan`, RAES blocking diagnostics, `build_aptl_realization_envelope()`, `BackendRealizationEnvelopeModel`, and snapshot provenance. All governed requirements precede mutation; no shell/Compose first-time selection and no `selected_values` map. |
| Rendering and effective model | `RuntimeConfiguration`, `DeploymentNodeRealization.runtime`, `_compose_node_generation._operational_config`, stateful lowering/graph/realization, and generated Compose validation. The static `docker-compose.yml` is not desired-state authority. |
| Runtime/stateful readback | `raes_runtime_observation`, `_raes_runtime_environment_observation`, `_runtime_concern_excess`, `_runtime_mount_observation`, `_raes_stateful_observation`, `raes_observation`, and the SEM-218 non-approximation gate. Extend these typed observers, rather than a product DTO or direct Docker path. |
| Certificates | `SOC_CERT_PROFILE`, `derive_soc_service_certs`, `ensure_soc_certs`, `_stateful_certificates`, selected-output mounts, and certificate evidence. Preserve the separate internal trust and host-facing lab-CA consumer boundaries. |
| Lifecycle/backend operations | `DeploymentBackend`, local/SSH Compose backends, `_compose_post_start`, `wait_for_realized_health`, `ReadinessPolling`, and the shared lifecycle/reset owner. No raw Docker subprocess, recreation retry, volume deletion on failure, or local-only behavior. |
| Secrets, errors, evidence | `load_dotenv`, `validate_required_env`, `find_placeholder_env_values`, `curl_safe`, `get_logger`, `redact`, `LabResult`, RAES diagnostics, and `RuntimeSnapshot`. Use stable secret-free classifications and redacted summaries, not a MISP exception hierarchy or native-response envelope. |

## Security And Host-Layer Guardrails

- **Parser/policy gates:** RAES strict Pydantic/semantic SDL validation,
  env-pack manifest/digest validation, realization-envelope capability checks,
  and plan interpretation must reject unknown, unsupported, incomplete, or
  unbound requirements before backend mutation.
- **Environment binding:** derive required `operator_secret` names from the
  admitted runtime; validate missing/placeholder input through the canonical
  dotenv helpers before `realize`. Compose interpolation emits a validated
  binding; it is not itself validation. Do not expand Wazuh-specific `EnvVars`
  into a MISP schema.
- **Secret/OS exposure:** no token/password/private key in process argv,
  Docker command, environment dump, generated Compose, logs, diagnostics,
  snapshots, provenance, test failures, or raw HTTP bodies. Use the existing
  safe HTTP/0600-file path or a backend exec boundary that keeps secret input
  off host argv, and keep artifact output containment/permissions checks.
- **Error/observability envelope:** distinguish unavailable transport, TLS or
  endpoint mismatch, authentication rejection, datastore failure, unexpected
  runtime state, malformed response, and timeout with bounded reason codes.
  Evidence records endpoint identity, selected verification outcome, elapsed
  time, readback outcome, and provenance—not credential values or response
  payloads.
- **Runtime/host closure:** observe Docker image/container config, image-owned
  environment baseline, container environment/command, mounts/volumes,
  capabilities, listeners/networks, generated artifacts, persistent volumes,
  and loopback publication. An image default may not silently satisfy a
  scenario-governed concern, and no convenience host publication is allowed.

The extensibility seam is the existing typed RAES runtime/stateful model plus
the envelope and `RuntimeSnapshot.realization_provenance`: the next service
with an admitted open value or authenticated native readiness uses those
generic surfaces. If image `Config.Env` or named-volume excess needs new
readback, add it to `DeploymentBackend`/the typed observation model so local
and SSH backends remain identical. Do not parameterize by product name or
encode MISP/Redis defaults in APTL.

## Proof Obligations And Boundaries

Regression coverage must establish: a fresh pack-backed realization reaches
authenticated MISP, Redis, and database readiness without changing the
realized container identities; normal persistence survives stop/start while
the explicit reset removes it; omitted/substituted/injected environment,
command, certificate mount, volume, listener, capability, or secret binding
fails closed; and backend-selected open values are independently observed with
correct provenance. Tests should build on pack-realization, runtime-observation,
stateful-realization/readiness, seed-boundary, and live-gate patterns already
in `tests/`, not shell-text assertions alone.

This issue does not repair general post-admission mutation enforcement (#915/
#916), redesign MISP or Redis, change the scenario's released persistence or
TLS posture, add a generic service-probe framework, alter intentional fixture
credentials, migrate static legacy Compose, or remove content seeders. Avoid
copying workaround/legacy literals into new config; treating absence as open;
using `pack_interaction` to inject deployment state; accepting health/TCP/seed
success as readiness; conflating certificate presence with activation, API
authentication with Redis authentication, or retained volume presence with
correct state; and deleting retained data to make a failure disappear.
