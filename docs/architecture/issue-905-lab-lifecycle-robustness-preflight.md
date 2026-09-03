# Issue #905 Lab Lifecycle Robustness Preflight

This note fixes the architecture boundary for interrupted and overlapping lab
lifecycle operations. It is guidance, not an implementation plan. No new ADR
is needed: ADR-045 already defines the lifecycle owner and ADR-046 already
requires every project lifecycle mutation to reuse
`.aptl/lifecycle/.lock`. Issue #905 requires the start, stop, clean-boot,
kill, monitor, retry, and API paths to honor that accepted contract.

## Decisions And Ownership Boundaries

Treat lifecycle ownership and residual runtime state as different facts:

| Fact | Required behavior |
| --- | --- |
| The shared lifecycle lock is held | Another owner is still mutating this project range. Fail before Docker or generated-state mutation with a stable, actionable busy result. Do not remove resources from under that owner. |
| The lock is free and project-owned containers or networks exist | A complete or partial range already exists without a current lifecycle owner. Normal start fails before RAES apply and SEM-218 evaluation, and directs the operator to the explicit stop or clean-boot workflow. |
| The lock is free and no project-owned runtime artifacts exist | Normal start may proceed through the existing RAES realization and readiness contract. |
| Presence cannot be determined | Fail closed as an observation error. An empty result caused by a Docker, transport, or parse failure is not proof that the range is absent. |

Normal start must not silently reconcile, stop, replace, or delete an existing
range. The safe default is a clear collision result. `aptl lab stop` remains
the non-volume reset, while `aptl lab stop -v` and `aptl lab start --clean`
remain the explicit destructive volume-reset surfaces. Persistent project
volumes alone are valid state for a stopped range and must not block normal
start.

Acquire the single project lifecycle mutation lock before `.env` hydration or
any other project-state or Docker mutation. Hold it through authoritative RAES
realization, readiness, and the late finalization steps. An OS lock, not lock
file existence or a stored PID, establishes ownership. Process death must
release ownership so that a subsequent stop can recover the abandoned range.
The lock must work across processes and threads on supported POSIX and Windows
hosts; ADR-045's current Windows in-process fallback is not sufficient for this
contract.

Clean boot and lifecycle enforcement are composite operations. They acquire
one outer owner and invoke stop/start through an explicit already-owned or
reentrant internal seam. They must not deadlock by acquiring the same lock
twice, release it between stop and start, or create a second lock namespace.
Read-only status may observe a transition without taking the exclusive lock,
but `LabStatus.running` must not be redefined to mean ownership, residue, or
realization success.

Teardown is idempotent and best effort to completion within one admitted
project identity. It removes directly materialized, project-labeled containers
before network removal can be attempted; requests Compose project teardown;
continues bounded project-scoped residual container and network cleanup even
when Compose reports an error; and verifies that project-owned runtime
artifacts are absent before reporting success. Default teardown preserves
volumes. The `-v` path uses the existing project-scoped volume inventory and
also reports aggregate failures. A current Compose file is not authoritative
for resources created by an interrupted or older realization.

The 900-second Compose health proof and authenticated stateful-service
readiness feed the SEM-218 realization contract. `docker compose up -d` or an
`Up` container state is not realization success. Issue #905 must not shorten,
detach, or bypass those checks merely to make the process exit sooner. Proven
duplicate waits may be removed only after showing that the same typed evidence
is already available. Asynchronous start would require durable job ownership,
cancellation, result retrieval, and API semantics and is outside this issue.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Public lifecycle boundary | `core.lab.orchestrate_lab_start()`, `stop_lab()`, `clean_boot_lab()`, `core.kill`, `cli.lab`, `cli.kill`, and the API lab router stay projections of one core lifecycle contract. Do not add CLI-, API-, or web-only collision logic. |
| Lifecycle ownership | Promote the `.aptl/lifecycle/.lock` convention from `lifecycle_enforce._single_owner_lock()` as required by ADR-045 and ADR-046. Reuse `LifecycleBusyError` semantics and the reentrant ownership pattern in `runstore`; add portable cross-process behavior and path-safe file creation rather than another lock or PID schema. |
| Configuration and identity | `AptlConfig` and `DeploymentConfig` remain the strict, `extra="forbid"` durable shapes. Validate `DeploymentConfig.project_name` once as a bounded Docker Compose project token because it scopes `-p`, label queries, and destructive volume-prefix cleanup. Profiles may use their existing stop fallback, but an invalid present config must not silently change destructive project identity to the default. Use the last admitted non-secret lifecycle/realization identity where the accepted ADR permits it, otherwise fail closed. |
| Environment and secrets | Keep `.env` admission in `load_dotenv()`, `env_vars_from_dict()`, and placeholder validation. This change needs no new environment variable or credential. ADR-029 redaction, `redact()`, owner-only generated files, and `curl_safe` remain mandatory. The lifecycle lock and presence probe must not parse or persist secrets. |
| Backend authority | `DeploymentBackend`, `DockerComposeBackend`, and `SshComposeBackend` own runtime inspection and mutation. Remote Docker keeps its admitted `DOCKER_HOST` and SSH identity environment. Core, CLI, and API code must not issue a second set of Docker commands or assume a local daemon. |
| Runtime identity and queries | Standard Compose resources use `com.docker.compose.project`; directly materialized containers also use `aptl.lifecycle.project`; realized networks use the project and realization labels. Build checked presence and cleanup on these admitted identities and generated realization metadata. Existing query helpers that return `[]` on command or parse failure cannot be used as proof of absence without preserving an error channel. Names and broad prefixes are not lifecycle authority. |
| Cleanup | Reuse `_compose_stop`, `_compose_lifecycle`, `_compose_base_substrate`, `_compose_network_realization`, and `_compose_volume_cleanup`. Preserve the label-bounded generic-container cleanup and volume inventory. Extend their orchestration instead of adding a shell cleanup script or daemon-wide prune. |
| Realization and readiness | Keep `start_lab_with_raes()`, generated RAES lifecycle artifacts, `wait_for_services_healthy()`, authenticated readiness, `_raes_stateful_observation`, `ReadinessPolling`, and `core.services.wait_for_service()`. Presence is an admission check, not a new realization verdict or a parsed SEM-218 message. |
| Results and errors | Keep `LabResult`, `StartupOutcome`, and `StartupDiagnostic` as the canonical core envelope, with existing CLI rendering and `LabActionResponse` projection. Busy, pre-existing, observation-failed, and cleanup-incomplete states need stable bounded diagnostics; they do not require a duplicate DTO or public exception hierarchy. Raw commands, Docker stderr, environment, credentials, host paths, or tracebacks must not cross the CLI/API/log envelope. |
| Authentication and web/API | The existing `verify_token`, BFF Host/CSRF/session gates, strict response model, loopback defaults, and web single-flight UI remain authoritative. An API `asyncio.wait_for()` timeout does not cancel its worker thread; the worker retains the lifecycle owner until it actually exits, and the response must continue to describe the outcome as unknown rather than success or cleanup authority. |
| Logging and observability | Use `get_logger()`, redaction, existing progress callbacks, and bounded structured fields. Record lifecycle stage, owner-busy versus residue-present classification, duration, resource counts, and cleanup verification. Do not log secret-bearing config, commands, raw backend output, process argv, or a PID as an authority token. No new OTel or persistence schema is needed. |
| Workflow and verification | Python changes require focused pytest coverage, `pytest`, the Ruff complexity gate, `pre-commit run --all-files`, and CI/Sonar checks from `.ground-control.yaml`. Changes to Compose, Dockerfiles, or `config/` also require the clean-lab gate on a fresh machine; the architecture does not require those artifact changes. |

## Security And Host-Layer Guardrails

- **Lock-file surface:** create and open the fixed project-local lock through
  the repository's no-follow, contained path helpers. The lifecycle directory
  and file must use owner-only permissions. Do not truncate or follow an
  operator-controlled symlink, and do not put secrets, argv, or authoritative
  owner metadata in the file.
- **Destructive identity:** validate the Compose project token before it
  reaches command argv, label filters, logs, or the `<project>_` volume-prefix
  query. A malformed or unknown identity blocks cleanup. It never falls back
  to a broader name match, current working directory guess, or daemon-wide
  prune.
- **Command and remote-host surface:** retain list-form subprocess arguments,
  explicit Compose project selection, scenario-root environment-file control,
  bounded timeouts/output, and the SSH backend's validated host, user, port,
  and key path. Do not interpolate a shell command or expose credentials in
  argv.
- **Runtime observation:** distinguish no resources from observation failure.
  Inspect all container states, including created and exited resources, and
  project-owned networks. A running-container-only query misses exactly the
  interrupted ranges in this issue.
- **Error envelope:** normalize and redact backend errors before placing them
  in `LabResult`, logs, API JSON, or CLI output. Operator guidance may name the
  safe APTL command to run, but it must not echo raw Docker output, environment
  values, filesystem paths, or secrets.
- **Mutation race:** every path that can start, stop, kill, retry, enforce, or
  clean a range uses the same owner. An emergency label does not authorize
  force-removing containers from under a live start.

## Extensibility Seam And Whole-Repository Scope

The required seam is one fixed mutation guard per admitted project directory.
That guard protects the selected deployment provider and validated project
name rather than creating a lock namespace for either value. Pair it with a
backend-owned checked observation of project runtime presence. The observation
keeps `present`, `absent`, and `observation failed` distinct and can later
support an explicit invocation-time collision policy such as `fail` or a
separately designed `reconcile`. The default for this issue remains `fail`.
Do not add an untyped option map or durable config flag.

Readiness duration remains parameterized through the existing polling/deadline
seams (`ReadinessPolling` and `wait_for_service()`), not hard-coded in a new
CLI/API branch. That preserves the next reasonable extension: a request-scoped
readiness or finalization budget that still produces the same authoritative
evidence. It does not authorize returning success before the proof completes.

The implementation must audit these repository and host surfaces together:

- `src/aptl/core/config.py`, `env.py`, `lab.py`, `lab_types.py`,
  `lifecycle_enforce.py`, `lifecycle_policy.py`, `kill.py`, `runstore.py`, and
  `utils/pathsafe.py`;
- the deployment protocol, Docker and SSH backends, checked queries, Compose
  stop/kill orchestration, base-substrate cleanup, network realization,
  volume inventory, service health, and stateful readiness;
- RAES start orchestration, generated lifecycle artifacts, stateful
  observation, and SEM-218 diagnostics;
- CLI lab/kill rendering, API dependencies/router/schemas, BFF and token
  gates, and the web lab client/types/single-flight behavior;
- `.aptl/lifecycle/.lock`, narrow lifecycle state, `.aptl/realization`, Docker
  containers/networks/volumes and labels, the local or remote Docker daemon,
  and native POSIX/Windows file-lock behavior;
- focused lifecycle/backend/API/CLI tests and the repository-wide workflow
  gates in `.ground-control.yaml` and `.gc/plan-rules.md`.

## Proof Obligations

Coverage must demonstrate the contract, not merely a happy-path command:

- a second start fails busy before RAES while the first owner is alive;
- stop and kill do not remove containers while start owns the project, but
  process death releases the lock and stop can reset the range;
- a free lock plus running, created, or exited project containers, or a
  project network, gives the clear pre-existing-range result without entering
  SEM-218 evaluation;
- a Docker, SSH transport, or parse failure during detection fails closed;
- cleanup handles mixed Compose and directly materialized resources, continues
  after a Compose error, removes networks only after attached project
  containers, verifies absence, and is idempotent;
- default teardown preserves volumes, `-v` removes only the validated
  project's volumes, and another project's resources remain untouched;
- CLI and API receive the same normalized `LabResult`, an API timeout does not
  free a still-running worker's owner, and remote Docker retains its backend
  environment;
- cross-process exclusion is exercised on POSIX and Windows, including
  composite clean-boot/enforcement ownership without nested-lock deadlock.

## Non-Goals And Anti-Patterns

This issue does not add arbitrary partial-RAES resume, implicit reconciliation,
a background start daemon, a durable job/cancellation API, new readiness or
SEM-218 semantics, multi-range tenancy, a new API/web/config schema, or a new
exception hierarchy. It does not change scenario models, profiles, secret or
certificate ownership, seed behavior, MCP setup, or volume persistence.

Avoid these anti-patterns:

- treating `containers are Up`, `LabStatus.running`, lock-file existence, or a
  PID file as proof of realization or ownership;
- parsing SEM-218 prose to discover a lifecycle collision;
- interpreting an empty unchecked Docker query as absence;
- auto-stopping or force-removing a range from normal start;
- releasing the owner between clean-boot stop and start, or before late
  mutating finalization finishes;
- returning immediately from teardown after the first Compose error;
- identifying resources only by `aptl-` names, current Compose membership, or
  broad prefixes; using `docker system prune` or an equivalent global cleanup;
- deleting `.env`, keys, `.mcp.json`, configuration, run archives, images, or
  volumes without the existing explicit destructive surface;
- shortening or backgrounding authoritative health/readiness checks under the
  guise of teardown robustness;
- duplicating lifecycle checks, DTOs, validators, polling loops, logging, or
  exception handling in CLI, API, web, RAES, or shell scripts.
