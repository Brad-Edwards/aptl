# Issue #910 Generated-Secret Environment Binding Preflight

This note fixes the architecture boundary for wiring TheHive to Cortex from
generated artifacts. It is guidance, not an implementation plan. No new ADR is
needed: ADR-029 owns control-plane secret handling, ADR-034 owns the SOC trust
boundary only where APTL owns the out-of-game host and control-plane surface,
ADR-046 and ADR-051 require admitted desired state plus independent readback,
and ADR-053 prevents pack/backend interaction providers from becoming
configuration providers. The environment pack owns in-game transport choices.

## Finding And Dependency Gate

Before implementation the repository pinned `raes==3.3.0` and
`raes-env-packs==4.0.2`.
APTL's generated-artifact path supports mount consumers only: the lowering DTO,
conflict checks, Compose override, image-free placement, evidence, and readback
all assume `mount_destination` plus `access_mode`.

The upstream schema dependency is now released. RAES 3.5.0 includes the
OpenRAE/rae#1074 `value_from` and generated-artifact environment-consumer
contract. The TechVault pack released in `raes-env-packs==5.1.0` uses that
contract for the Cortex initializer credentials and TheHive's
`TH_CORTEX_KEYS`, and it declares authenticated Cortex enrichment evidence.
Those releases satisfy the API-key half of the dependency gate and are the
versions APTL must consume together.

The released pack intentionally uses the in-network HTTP path and therefore does
not declare a TheHive HTTPS keystore-password environment consumer. That is an
authoritative in-game environment choice, not a missing APTL prerequisite. APTL
must materialize the generated consumers the admitted pack declares; it must not
infer an env-file consumer from a mount, patch the staged pack, require HTTPS, or
introduce a TheHive-specific fallback. If a future pack chooses HTTPS and
declares another generated-secret consumer, the same generic affordance must be
able to materialize it.

The dependency update is one compatibility unit: exact RAES and env-pack pins,
the lockfile, the env-pack content digest, the pack/backend interaction provider,
and the digest-bound TechVault verifier must agree. A successful parse against a
locally edited or unreleased package is not completion evidence.

## Decisions And Ownership Boundaries

1. **The env-pack owns the dependency graph.** The released TechVault pack
   declares the generated output, its `secret` sensitivity, the selected output,
   the TheHive consumer, the environment or env-file delivery kind, and all
   ordering/refresh dependencies. APTL must not recognize `thehive`, `cortex`,
   `TH_CORTEX_KEYS`, or `HTTPS_KEYSTORE_PASSWORD` in generic lowering or
   rendering code.
2. **RAES owns the portable schema and validation.** Use the released
   generated-secret and consumer-binding models, compiler projection, planner
   diagnostics, concern path, and non-approximation comparison. Evolve the
   existing APTL generated-artifact realization value only enough to preserve
   the upstream binding discriminant. Do not create a parallel Pydantic model,
   YAML parser, or second validation vocabulary.
3. **Keep three secret classes distinct.** An `operator_secret` is an explicit
   operator grant sourced through the existing `.env` boundary; a
   `secret_fixture` is authored vulnerable scenario content; a generated secret
   is backend-created state governed by a generated artifact and its lifecycle.
   Generated service credentials are not ambient operator input, authored
   fixture values, SDL variables, or durable `AptlConfig` fields.
4. **Honor declared producer ownership.** Generate and deliver exactly the
   selected outputs declared by each admitted generated artifact. Existing
   certificate generators retain ownership of their declared outputs, but APTL
   does not require a pack to consume a keystore password through the
   environment. A generated service key uses the released generic
   secret-generator profile supported by APTL, not a product-named writer.
5. **Generated artifacts precede consumers.** Generation and validation happen
   in the existing stateful-prerequisite phase, before effective Compose model
   validation and before any consumer starts. The key's registration with
   Cortex and delivery to TheHive must share one artifact identity and declared
   dependency chain. Ordinary restart reuses a still-valid artifact consistently;
   rotation or clean reset cannot update only one side.
6. **Secret bytes never enter generated Compose.** For an image-backed consumer,
   generated Compose contains only a contained env-file path and non-secret
   binding metadata. A direct environment affordance is still implemented via an
   owner-only backend env file; it is not rendered as `NAME=<secret>` and is not
   passed with `docker ... -e NAME=<secret>`. Image-free consumers reuse the
   existing `--env-file <path>` backend pattern, extended from artifact-backed
   input rather than ambient `.env` lookup.
7. **Readback proves the association, not merely presence.** The backend compares
   the generated selected output with the exact realized container environment
   in memory and then discloses only the upstream secret-safe commitment or a
   boolean match. An env-file path in YAML, a non-empty variable, container
   health, or an echo of the planned consumer is insufficient. Secret values and
   reusable unsalted hashes do not enter evidence.
8. **Semantic readiness remains distinct from delivery.** Completion requires an
   authenticated observation that TheHive exposes the expected Cortex analyzer
   integration. Prefer a pack-authored RAES readiness/assertion consumed by the
   existing evaluator when the released contract supplies it; otherwise the
   digest-bound TechVault scenario-verifier plugin owns the answer key through a
   bounded scenario-neutral operation. Generic APTL core and the live gate must
   not acquire a TheHive/Cortex special case.
9. **Failure is fatal at the owning layer.** Invalid declarations and unsupported
   bindings fail before Docker mutation. Generation, secure-write, registration,
   delivery, equality-readback, or analyzer-readiness failure returns an
   unsuccessful existing result envelope. It is not a seed warning, degraded
   success, or instruction to perform a manual post-boot repair.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Pack acquisition | `ScenarioSourceConfig`, `resolve_scenario_bundle()`, `env_pack_bundle()`, `ScenarioBundle`, env-packs `validate_pack()` / `validate_pack_content_manifest()`, pack manifests and content digests. Never edit the staged pack or parse its manifest again. |
| RAES shape and admission | Released RAES generated-artifact/consumer models, strict Pydantic parsing, semantic cross-reference validation, `RuntimeManager.plan()`, `AptlProvisioner`, planner diagnostics, the realization concern registry, and SEM-218 non-approximation. Unknown binding kinds, missing outputs, ambiguous consumers, and unsupported capability claims block planning. |
| Capability honesty | `create_aptl_manifest()` and its `ProvisionerCapabilities.supported_generated_artifact_kinds`, realization envelope, and observation claims. Advertise the released generated-secret kind/binding only after generation, both delivery routes, and readback work end to end. |
| Typed lowering | `raes_stateful_realization`, `DeploymentGeneratedArtifactRealization`, its existing consumer/output values, and `DeploymentRealizationSpec`. Preserve one closed binding kind and mutually exclusive destination fields; do not force an env binding into `mount_destination` or add a product DTO. |
| Generation and storage | `_realize_stateful_prerequisites()`, `_realize_one_generated_artifact()`, `_canonical_generated_path()`, `_ensure_secure_dir()`, `_atomic_write_secure()`, and the SOC CA generator's atomic `0600` password output. Generated values live under the writable realization root, never the pristine pack or a tracked path. |
| Compose and image-free delivery | `_compose_stateful_model`, `_compose_stateful_graph`, `_compose_stateful_realization`, `_compose_node_generation`, `_compose_base_substrate`, `_compose_model_realization`, and the mixed-realization ordering. Extend the existing renderer/validator by binding kind; do not add a second Compose generator or raw `docker` path. |
| Readback and satisfaction | `raes_runtime_observation`, `_raes_stateful_observation`, `_runtime_concern_disclosure`, `artifact_spec()`, RAES `RuntimeSnapshot`, and the final realization-disclosure gate. Compare secret bytes only in process, discard them immediately, and disclose metadata/match state only. |
| Service mutation and readiness | Existing declared service-materialization/evaluator contracts where applicable, bounded backend container operations, `ReadinessPolling`, and the scenario-verifier seam. Any Cortex registration is an admitted, idempotent operation with independent authenticated readback; `seed-prime.sh` is not a realization authority. |
| Errors and logging | RAES `Diagnostic`, `diagnostic()`, `render_raes_diagnostics()`, `ApplyResult`, `LabResult`, `BackendTimeoutError`, `get_logger()`, and `redact()`. Use stable core-authored categories and bounded messages; do not add a Cortex exception tree. |
| Persistence and evidence | Generated ignored state, `RangeSnapshot.to_dict()`, `LocalRunStore` redacting structured writes, `raes_repro`, and backend evidence. Persist artifact identity, binding kind, consumer identity, lifecycle, and pass/fail only; never copy generated secret files into a run archive. |
| Supply chain and workflow | `pyproject.toml`, `uv.lock`, package/digest assertions, asset exclusion tests, `pytest`, the static TechVault gate, `pre-commit run --all-files`, and the clean `aptl lab stop -v && aptl lab start` gate required by `.gc/plan-rules.md` when Compose or `config/` changes. |

## Security And Host-Layer Passage

| Layer | Required behavior |
| --- | --- |
| Auth and ingress | Issue #910 adds no API, UI, CLI, query parameter, or configuration authoring surface. APTL-owned host and control-plane interfaces remain behind the existing bearer/session, Host, CSRF, and BFF gates. The pack remains authoritative for in-game service protocols. No response exposes whether a specific secret value was generated. |
| Pack and RAES validators | Env-pack inventory/digest validation runs before parsing; RAES then enforces the released closed shape, target/output references, sensitivity, delivery discriminant, ordering, and backend support. APTL consumes the admitted result and does not normalize invalid input into a default. |
| APTL shape checks | Lowering resolves one admitted node to one backend service, selects only declared non-`producer_private` output, and rejects duplicates or incompatible fields. Destination-conflict checks cover environment names and env-file delivery as well as mount paths; separate namespaces must not be compared as if they were one path. |
| Env-file format | A generated env file is a bounded UTF-8 assignment with a validated variable name, no NUL/newline injection, no duplicate key, a non-empty non-placeholder value, and an explicit selected output. Use the upstream format declaration; do not guess from a `.password` suffix or parse arbitrary shell syntax. |
| Secret at rest | Parent directories are owner-only; secret files are created/replaced atomically as `0600`; every component and leaf is containment- and no-follow-checked on create and reuse. `.gitignore` and package exclusions remain defense in depth. The known path-following weakness tracked by #966 must not be copied into this path. |
| Compose validation | Validate the merged effective model without resolving or printing env-file contents. `--no-interpolate` alone is not assumed to suppress env-file expansion; use Compose's no-env-resolution mode or an equivalently secret-free structural validation path, and never log/copy captured config output. |
| OS/process exposure | Only env-file paths may appear in host argv. Secret values never appear in `docker compose` arguments, `docker exec` arguments, shell command strings, process titles, or host logs. Docker-root users and the intended container process can inspect container environment by design; no additional consumer receives it. |
| Registration transport | If a native Cortex API operation is required, the key is read from the admitted container environment or a mounted secret within the container, or transported through an existing secret-safe typed boundary. The current `cortex-apikey.sh` bearer header in `docker exec` argv, stdout return, prefix logging, and `.env` copy are not admissible for a generated control-plane key. |
| Runtime observation | Docker inspect may expose environment bytes to the trusted backend process. Observation may use them only for exact in-memory comparison, never logging, exception construction, DTO details, snapshots, provenance, or persistence. Presence-only evidence does not prove that Cortex and TheHive share the same key. |
| Error envelope | Diagnostics may name the artifact address, consumer, stage, and stable failure class. They omit secret values, env-file bodies, authorization headers, native response bodies, raw Compose output/stderr, and tracebacks. `redact()` remains defense in depth, not permission to serialize the value first. |

## Extensibility Seam

The seam is the released generated-artifact consumer binding:

`(artifact address, selected output, binding kind, target node, environment
target, lifecycle/dependencies) -> typed backend delivery + independent
readback`.

The renderer and observer dispatch on the upstream binding kind, while generator
support stays a finite manifest capability. The next generated database token or
service password should require a pack declaration and an already-supported
generator/binding, not edits keyed to a service or variable name. A future
secret-file/secret-store backend can implement the same admitted binding without
changing the pack schema, lifecycle workflow, evidence envelope, or semantic
verifier.

## Gotchas And Anti-Patterns

- Do not add `CORTEX_API_KEY`, `TH_CORTEX_KEYS`, or the keystore password to
  `EnvVars`, `hydrate_dotenv()`, `AptlConfig`, process environment defaults, or
  an APTL scenario-name table.
- Do not use SDL variables, `operator_secret`, `secret_fixture`, generated
  artifact outputs, and Compose interpolation as interchangeable mechanisms.
- Do not retain `config/cortex/thehive-cortex.env` or the deterministic fallback
  in `cortex-apikey.sh` as the env-pack's hidden source of truth. A legacy static
  Compose fixture, if still supported, is not evidence for the env-pack route.
- Do not render secret values into `compose-base.yml`, a stateful override,
  diagnostics, test assertion messages, snapshots, provenance, or verifier
  reports.
- Do not treat `env_file:` presence, `Config.Env` name presence, container health,
  a successful API mutation, or Cortex port reachability as analyzer-integration
  proof.
- Do not generate one key for TheHive and a second key for Cortex, rotate one side
  independently, or overwrite a retained Cortex identity on every restart.
- Do not weaken `producer_private`, selected-output, sensitivity, remote-daemon,
  path-containment, or exact-readback checks to admit the new delivery kind.
- Do not create a TheHive/Cortex branch in RAES adapters, Compose rendering,
  generic readiness, cleanup, or the core live gate.
- Do not make SOC seeding a realization repair. A seed may add scenario content
  after readiness; it may not make an undeclared credential binding true or turn
  a failed integration into a warning.
- Do not expose the generated key through script stdout or persist it into the
  project `.env` for MCP clients. TheHive-to-Cortex authentication and MCP client
  authentication are different credentials and boundaries.

## Non-Goals And Implementation Boundary

This issue does not redesign the RAES schema, environment packs, `AptlConfig`,
`EnvVars`, general secret management, Docker isolation, pack-authored SOC TLS or
Cortex HTTPS choices, MCP credentials, or the scenario-verifier contract. It does not solve all
remaining post-admission TechVault mutations tracked by #915, all open/closed
runtime closure tracked by #916, operator grant policy tracked by #965, or the
general generated-env-file hardening tracked by #966; it must nevertheless avoid
contradicting or bypassing those boundaries.

The implementation boundary is consumption of the released RAES affordance and
released TechVault declaration; generic typed lowering and secure local delivery;
read-after-write without secret disclosure; idempotent agreement with Cortex;
and a clean-boot semantic proof that TheHive exposes working Cortex analyzers
without manual repair.
